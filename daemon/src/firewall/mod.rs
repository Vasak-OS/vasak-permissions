//! El lado userspace del cortafuegos por aplicación (M0 del issue #93).
//!
//! Carga el programa BPF commiteado (`vasak-firewall.bpf.o`, compilado desde el
//! crate `firewall-ebpf`), lo adjunta al cgroup v2 unificado raíz y ofrece una
//! API mínima para marcar y desmarcar un pid en el mapa `BLOCKED`. Mientras un
//! pid esté marcado, el programa BPF corta sus `connect()` (egreso, IPv4 e IPv6).
//!
//! # Qué hace y qué NO hace este módulo
//!
//! Hace *sólo* la infraestructura: cargar, adjuntar y escribir el mapa. **No**
//! decide a quién bloquear —eso es la capa de política, que llega en un PR
//! siguiente— ni sincroniza el mapa con los procesos vivos. Acá sólo vive la
//! mecánica de eBPF, aislada para poder razonarla y endurecerla por separado.
//!
//! # Alcance del bloqueo: sólo `connect()`
//!
//! El programa engancha `connect4`/`connect6`, así que corta el egreso que pasa
//! por `connect()` —TCP y UDP *conectado*—. Un proceso marcado todavía puede
//! mandar por UDP **no conectado** (`sendto`/`sendmsg` sin `connect()` previo,
//! como QUIC/HTTP3 sobre un socket no conectado): esos no pegan en este gancho.
//! Por eso no es un «kill-switch» total de red, sino un corte del egreso por
//! `connect()`. Cerrar esa vía es un hito posterior que suma
//! `cgroup/sendmsg4`/`sendmsg6` compartiendo este mismo veredicto y el mismo
//! mapa `BLOCKED`; hasta entonces el alcance es el de `connect()`.
//!
//! # Por qué se engancha en la raíz y filtra por pid
//!
//! Todas las aplicaciones comparten el cgroup de `vasak-desktop` (el lanzador
//! hace `spawn()` pelado, sin cgroup por app), así que el punto de enganche no
//! puede separarlas. La precisión por aplicación la da el **mapa por pid**, no el
//! cgroup: se engancha alto —la raíz unificada, una sola carga para todo el
//! equipo— y el programa ve a todos los procesos pero sólo corta los pids que el
//! daemon marcó. Por eso la clave lleva el uid (`(uid << 32 | pid)`): en la raíz
//! conviven los pids de todas las sesiones.
//!
//! # Falla cerrado y ruidoso
//!
//! Si no se puede cargar o adjuntar el programa, [`Firewall::load`] devuelve
//! `Err` con el motivo; no hay un camino silencioso en el que el daemon crea que
//! el cortafuegos está activo cuando no lo está. Quien lo llame decide qué hacer
//! con ese error (el cableado con la política, en el PR siguiente, define si el
//! arranque se aborta o se degrada con aviso).
//!
//! # Por qué un trait por delante de aya
//!
//! El motor eBPF real ([`MotorAya`]) es I/O privilegiado puro: cargar el objeto,
//! adjuntar los programas y escribir el mapa son syscalls `bpf()` que sólo salen
//! bien como root. Para poder probar la **lógica** —la derivación de la clave,
//! la clasificación del error de `unblock`, el flujo de adjuntar los dos
//! programas y los mensajes accionables— sin ser root, esa lógica vive en
//! [`Firewall`] sobre el trait [`MotorBpf`], y las pruebas la ejercitan con un
//! motor de mentira. El adapter sobre aya queda fino y sin más lógica que las
//! propias syscalls.

pub mod conexiones;
pub mod dns;
pub mod dominio;
pub mod enrolar;
pub mod mapa;

use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;

use aya::maps::{HashMap as BpfHashMap, MapError};
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::sys::SyscallError;
use aya::Ebpf;

/// El cgroup v2 unificado raíz, ancestro de toda la sesión del usuario.
const CGROUP_RAIZ: &str = "/sys/fs/cgroup";

/// El nombre del mapa en el objeto BPF (el del `static` en `firewall-ebpf`).
/// Si se renombra allá y no acá, la carga falla en vez de escribir en silencio
/// un mapa que no existe.
const MAPA_BLOQUEADOS: &str = "BLOCKED";

/// El valor que el programa BPF interpreta como «denegar». Tiene que coincidir
/// con `DENY` del lado BPF; es un único byte para dejar lugar a más política sin
/// cambiar la forma del mapa.
const DENY: u8 = 1;

/// El tope de entradas del mapa `BLOCKED`. **Tiene que coincidir** con el
/// `with_max_entries` del programa BPF; una prueba lo ata a la fuente. Importa
/// para el fail-closed: un `insert` sobre el mapa lleno falla, y un corte que no
/// se aplica es un control de seguridad ausente, no un detalle.
const CAPACIDAD_BLOCKED: usize = 4096;

/// El nombre del mapa del bloqueo por dominio (M2), el del `static` en
/// `firewall-ebpf`. Igual que `BLOCKED`: si se renombra allá y no acá, escribirlo
/// falla en vez de hacerlo en silencio sobre un mapa que no existe.
const MAPA_DOMINIO: &str = "DOMAIN_BLOCKED";

/// El tope de entradas de `DOMAIN_BLOCKED`. **Tiene que coincidir** con el
/// `with_max_entries` del programa BPF; una prueba lo ata a la fuente. Importa
/// para el fail-closed, igual que [`CAPACIDAD_BLOCKED`].
const CAPACIDAD_DOMINIO: usize = 4096;

/// Los dos programas `cgroup/connect` que se adjuntan a la raíz, en orden.
const PROGRAMAS: [&str; 2] = ["connect4", "connect6"];

/// La clave de `DOMAIN_BLOCKED`: la misma clave de pid de `BLOCKED`
/// (`uid << 32 | pid`) más la IP de destino en 16 bytes (IPv4 en los primeros 4,
/// los 16 de IPv6). **`repr(C)` y byte a byte idéntica** a la del programa BPF
/// (`firewall-ebpf::DomainKey`): una prueba de correspondencia ata los dos lados.
/// `Pod` para que aya la escriba como clave cruda del mapa.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DomainKey {
    /// `uid << 32 | pid`, idéntica a la clave de `BLOCKED`.
    pid_key: u64,
    /// IP de destino en 16 bytes, mismo formato que `ConnectionEvent.dst`.
    ip: [u8; 16],
}

// SAFETY: `DomainKey` es `repr(C)`, `Copy` y sin punteros ni padding con
// significado: una secuencia de bytes cualquiera de su tamaño es un valor válido,
// que es lo que `aya::Pod` exige para usarla como clave cruda del mapa.
unsafe impl aya::Pod for DomainKey {}

/// Arma la clave de dominio. Acá —como [`clave`]— porque es el punto exacto donde
/// el daemon y el programa BPF se pueden desincronizar sin que nada avise.
fn clave_dominio(pid_key: u64, ip: [u8; 16]) -> DomainKey {
    DomainKey { pid_key, ip }
}

/// El motor eBPF visto por la lógica del cortafuegos: lo justo para adjuntar un
/// programa y marcar o desmarcar un pid en el mapa `BLOCKED`.
///
/// Existe como trait para separar la lógica de `Firewall` del I/O privilegiado
/// de aya: [`MotorAya`] lo implementa con syscalls reales (sólo corre como
/// root), y las pruebas lo implementan con un motor de mentira para ejercitar la
/// lógica sin privilegios.
pub trait MotorBpf {
    /// Carga y adjunta el programa `nombre` al cgroup raíz.
    fn adjuntar(&mut self, nombre: &str) -> Result<(), String>;

    /// Escribe `clave → valor` en el mapa `BLOCKED`.
    fn insertar(&mut self, clave: u64, valor: u8) -> Result<(), MapError>;

    /// Quita `clave` del mapa `BLOCKED`.
    fn quitar(&mut self, clave: u64) -> Result<(), MapError>;

    /// Marca la pareja `(clave de pid, IP) → DENY` en `DOMAIN_BLOCKED` (M2): a
    /// partir de ahora el programa corta el `connect()` de ese pid a esa IP.
    fn insertar_ip(&mut self, pid_key: u64, ip: [u8; 16]) -> Result<(), MapError>;

    /// Quita la pareja `(clave de pid, IP)` de `DOMAIN_BLOCKED`.
    fn quitar_ip(&mut self, pid_key: u64, ip: [u8; 16]) -> Result<(), MapError>;
}

/// El cortafuegos cargado: es dueño del motor eBPF y, a través de él, del
/// programa adjunto y su mapa. Mientras vive, los programas siguen adjuntos; al
/// soltarlo, se desadjuntan.
pub struct Firewall<M: MotorBpf = MotorAya> {
    motor: M,
}

impl Firewall<MotorAya> {
    /// Carga el objeto commiteado y adjunta `connect4`/`connect6` al cgroup raíz.
    ///
    /// El objeto se embebe en el binario con `include_bytes_aligned!`: no hay un
    /// `.o` que ubicar en runtime, coherente con el daemon de un solo binario, y
    /// el build estable no necesita nightly ni `bpf-linker` para producirlo.
    pub fn load() -> Result<Self, String> {
        Self::con_motor(MotorAya::cargar()?)
    }

    /// Toma el ring buffer `EVENTS` del cortafuegos para el mapa en vivo (M1).
    ///
    /// Se extrae del `Ebpf` (deja de estar en él), así que se llama **una vez**,
    /// justo después de cargar, antes de envolver el cortafuegos en el `Enforcer`.
    /// El mapa `BLOCKED` sigue en el `Ebpf` para las escrituras del enforcement;
    /// el ring buffer es independiente y se lo lleva el lector. `None` si el objeto
    /// no trae el ring (no debería: lo declara el mismo programa).
    pub fn tomar_eventos(&mut self) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        self.motor.tomar_eventos()
    }
}

impl<M: MotorBpf> Firewall<M> {
    /// Adjunta los dos programas al cgroup raíz y envuelve el motor.
    ///
    /// El flujo compartido por el motor real y el de prueba: si adjuntar
    /// cualquiera de los dos falla, se devuelve el error y no queda un
    /// cortafuegos a medio adjuntar que se crea activo.
    fn con_motor(mut motor: M) -> Result<Self, String> {
        for nombre in PROGRAMAS {
            motor.adjuntar(nombre)?;
        }
        tracing::info!(
            "Cortafuegos por aplicación cargado y adjunto a {CGROUP_RAIZ} (connect4/connect6)"
        );
        Ok(Self { motor })
    }

    /// Marca un pid como bloqueado: a partir de ahora el programa corta sus
    /// `connect()`. Idempotente (reescribe la misma clave).
    pub fn block(&mut self, uid: u32, pid: u32) -> Result<(), String> {
        self.motor.insertar(clave(uid, pid), DENY).map_err(|e| {
            let base = format!(
                "no se pudo marcar el pid {pid} (uid {uid}): {}",
                con_causas(&e)
            );
            // Fail-closed explícito ante el mapa lleno: se nombra la causa para
            // que el llamador lo registre ruidoso en vez de creer que el corte
            // quedó aplicado. Ver [`Enforcer::bloquear`].
            if es_mapa_lleno(&e) {
                format!(
                    "{base}. El mapa BLOCKED está lleno (tope {CAPACIDAD_BLOCKED}): \
                     el corte de red de ese proceso NO se está aplicando"
                )
            } else {
                base
            }
        })
    }

    /// Desmarca un pid: sus `connect()` vuelven a pasar. No es error desmarcar uno
    /// que no estaba (el proceso pudo salir y ya haberse limpiado).
    pub fn unblock(&mut self, uid: u32, pid: u32) -> Result<(), String> {
        match self.motor.quitar(clave(uid, pid)) {
            Ok(()) => Ok(()),
            // Una clave ausente no es un fallo: desmarcar lo que ya no está es
            // llegar al mismo estado deseado. Ver [`es_clave_ausente`].
            Err(e) if es_clave_ausente(&e) => Ok(()),
            Err(e) => Err(format!(
                "no se pudo desmarcar el pid {pid} (uid {uid}): {}",
                con_causas(&e)
            )),
        }
    }

    /// Corta una IP para un pid por una regla de dominio (M2): mete
    /// `(pid_key, ip) → DENY` en `DOMAIN_BLOCKED`. Fail-closed: un mapa lleno da un
    /// error que lo nombra, para que el llamador lo registre ruidoso en vez de
    /// creer que el corte quedó aplicado.
    pub fn bloquear_ip(&mut self, pid_key: u64, ip: [u8; 16]) -> Result<(), String> {
        self.motor.insertar_ip(pid_key, ip).map_err(|e| {
            let base = format!(
                "no se pudo cortar la IP {} para la clave de pid {pid_key:#x} (dominio): {}",
                ip_texto(&ip),
                con_causas(&e)
            );
            if es_mapa_lleno(&e) {
                format!(
                    "{base}. El mapa DOMAIN_BLOCKED está lleno (tope {CAPACIDAD_DOMINIO}): \
                     el corte por dominio de esa IP NO se está aplicando"
                )
            } else {
                base
            }
        })
    }

    /// Descorta una IP de un pid. No es error quitar una que no estaba (el proceso
    /// pudo salir, o el TTL ya la bajó), igual que [`Self::unblock`].
    pub fn desbloquear_ip(&mut self, pid_key: u64, ip: [u8; 16]) -> Result<(), String> {
        match self.motor.quitar_ip(pid_key, ip) {
            Ok(()) => Ok(()),
            Err(e) if es_clave_ausente(&e) => Ok(()),
            Err(e) => Err(format!(
                "no se pudo descortar la IP {} para la clave de pid {pid_key:#x} (dominio): {}",
                ip_texto(&ip),
                con_causas(&e)
            )),
        }
    }
}

/// Texto legible de una IP en 16 bytes, para los mensajes de error: IPv4 si los
/// últimos 12 bytes son cero, IPv6 si no.
fn ip_texto(ip: &[u8; 16]) -> String {
    if ip[4..].iter().all(|&b| b == 0) {
        std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string()
    } else {
        std::net::Ipv6Addr::from(*ip).to_string()
    }
}

/// El cortafuegos más la contabilidad de **qué pids tenemos marcados**, con qué
/// uid. Es la capa que la política maneja; `Firewall` es sólo el mapa.
///
/// # Por qué hace falta recordar el uid de cada pid marcado
///
/// La clave del mapa es `(uid << 32 | pid)`, así que para desmarcar un pid hay
/// que saber con qué uid se marcó. Cuando un proceso **sale**, su `/proc/<pid>`
/// ya no está y el aviso de salida del conector no trae el uid: sin esta tabla
/// no se podría limpiar su entrada, y un pid reciclado heredaría un corte que no
/// le corresponde. Por eso `bloquear` anota `pid → uid` y `limpiar` lo usa.
///
/// # Fail-closed
///
/// `bloquear` **no** anota el pid como marcado si la escritura del mapa falla
/// (mapa lleno, u otro): no se finge que el corte está aplicado cuando no lo
/// está. El error se devuelve para que el llamador lo registre ruidoso.
///
/// Genérico sobre [`MotorBpf`] por lo mismo que `Firewall`: la contabilidad y la
/// reconciliación se prueban sin root con el motor de mentira.
pub struct Enforcer<M: MotorBpf = MotorAya> {
    firewall: Firewall<M>,
    /// `pid → uid` de los que tenemos marcados con el kill-switch de M0.
    marcados: HashMap<u32, u32>,
    /// Los pids enrolados por una regla de dominio (M2) y las IPs que les tenemos
    /// cortadas ahora mismo en `DOMAIN_BLOCKED`. Es el espejo en userspace del
    /// mapa BPF: hace falta para quitar las entradas al salir el pid (su `/proc`
    /// ya no está) y para diferenciar qué agregar y qué quitar al reconciliar.
    dominio: HashMap<u32, DomPid>,
}

/// Un pid enrolado por regla de dominio: con qué uid y ejecutable, y las IPs que
/// le tenemos cortadas. El ejecutable se guarda para reconciliar por binario
/// cuando el snoop ata una IP nueva a un dominio que ese binario bloquea.
struct DomPid {
    uid: u32,
    binary: String,
    ips: HashSet<[u8; 16]>,
}

impl<M: MotorBpf> Enforcer<M> {
    pub fn nuevo(firewall: Firewall<M>) -> Self {
        Self {
            firewall,
            marcados: HashMap::new(),
            dominio: HashMap::new(),
        }
    }

    /// Marca `(uid, pid)` y lo anota como vivo. Idempotente. Fail-closed: si la
    /// escritura del mapa falla, **no** lo anota —no fingimos que está cortado— y
    /// devuelve el error.
    pub fn bloquear(&mut self, uid: u32, pid: u32) -> Result<(), String> {
        self.firewall.block(uid, pid)?;
        self.marcados.insert(pid, uid);
        Ok(())
    }

    /// Quita la marca de un pid **que nosotros marcamos** —al salir el proceso o
    /// al apagar el switch—. No hace nada si no lo teníamos marcado. Usa el uid
    /// anotado, que es la única forma de reconstruir la clave una vez que el
    /// proceso ya no está.
    ///
    /// Limpia **las dos** capas: el kill-switch de M0 (`BLOCKED`) y, si el pid
    /// estaba enrolado por una regla de dominio, sus IPs cortadas en
    /// `DOMAIN_BLOCKED`. Un pid reciclado heredaría un corte ajeno si no se
    /// limpiaran, así que se quitan las dos al salir.
    pub fn limpiar(&mut self, pid: u32) -> Result<(), String> {
        if let Some(dom) = self.dominio.remove(&pid) {
            let pid_key = clave(dom.uid, pid);
            for ip in dom.ips {
                // Mejor esfuerzo: el proceso ya salió, así que una IP que no se
                // pueda quitar no bloquea nada vivo; se registra y se sigue.
                if let Err(e) = self.firewall.desbloquear_ip(pid_key, ip) {
                    tracing::warn!("Cortafuegos (dominio): al limpiar el pid {pid}: {e}");
                }
            }
        }
        if let Some(uid) = self.marcados.remove(&pid) {
            self.firewall.unblock(uid, pid)?;
        }
        Ok(())
    }

    /// Lleva el bloqueo por dominio de un pid al día. `tiene_reglas` dice si su
    /// binario tiene **alguna** regla de dominio ahora; `deseadas`, las IPs que
    /// debería cortar (vacío si todavía nadie resolvió esos dominios).
    ///
    /// # Por qué `tiene_reglas` aparte de `deseadas`
    ///
    /// Un pid de un binario con regla se **enrola** (queda anotado) aunque todavía
    /// no haya IPs que cortar: si no, el empujón del snoop
    /// ([`Self::reconciliar_dominio_binario`]) —que sólo alcanza a los pids
    /// enrolados— nunca llegaría a él, y la regla no cortaría nada. Así que con
    /// `tiene_reglas` el pid queda enrolado con IPs vacías; sin reglas, se limpia y
    /// sale del enrolado.
    ///
    /// Fail-closed: una IP deseada que no se pudo escribir **no** queda anotada
    /// como aplicada —no se finge un corte que no está— y el error sube; se
    /// reintenta en el próximo reconcile. Una IP que no se pudo quitar se deja
    /// anotada para reintentar quitarla.
    ///
    /// Devuelve los errores sin cortar, como [`Self::reconciliar`].
    pub fn reconciliar_dominio_pid(
        &mut self,
        uid: u32,
        pid: u32,
        binary: &str,
        deseadas: HashSet<[u8; 16]>,
        tiene_reglas: bool,
    ) -> Vec<String> {
        let mut errores = Vec::new();

        // Binario sin reglas: nada que enrolar. Si estaba enrolado, se limpia
        // entero (la regla se borró), quitando sus IPs del mapa.
        if !tiene_reglas {
            if let Some(dom) = self.dominio.remove(&pid) {
                let pid_key = clave(dom.uid, pid);
                for ip in dom.ips {
                    if let Err(e) = self.firewall.desbloquear_ip(pid_key, ip) {
                        errores.push(e);
                    }
                }
            }
            return errores;
        }

        let actuales = self
            .dominio
            .get(&pid)
            .map(|d| d.ips.clone())
            .unwrap_or_default();
        let pid_key = clave(uid, pid);
        let mut aplicadas = actuales.clone();
        for &ip in deseadas.difference(&actuales) {
            match self.firewall.bloquear_ip(pid_key, ip) {
                Ok(()) => {
                    aplicadas.insert(ip);
                }
                Err(e) => errores.push(e),
            }
        }
        for &ip in actuales.difference(&deseadas) {
            match self.firewall.desbloquear_ip(pid_key, ip) {
                Ok(()) => {
                    aplicadas.remove(&ip);
                }
                Err(e) => errores.push(e),
            }
        }

        // Queda enrolado aunque `aplicadas` esté vacío: el binario tiene reglas, y
        // el pid tiene que estar enrolado para que el empujón del snoop lo alcance.
        self.dominio.insert(
            pid,
            DomPid {
                uid,
                binary: binary.to_string(),
                ips: aplicadas,
            },
        );
        errores
    }

    /// Reconcilia **todos** los pids vivos enrolados de un `(uid, binary)` contra
    /// `deseadas`. Es lo que corre cuando el snoop de DNS ata una IP nueva a un
    /// dominio que ese binario bloquea: cada pid enrolado del binario toma el
    /// conjunto de IPs al día. `tiene_reglas` se pasa tal cual a cada pid.
    pub fn reconciliar_dominio_binario(
        &mut self,
        uid: u32,
        binary: &str,
        deseadas: HashSet<[u8; 16]>,
        tiene_reglas: bool,
    ) -> Vec<String> {
        let pids: Vec<u32> = self
            .dominio
            .iter()
            .filter(|(_, d)| d.uid == uid && d.binary == binary)
            .map(|(pid, _)| *pid)
            .collect();
        let mut errores = Vec::new();
        for pid in pids {
            errores.extend(self.reconciliar_dominio_pid(
                uid,
                pid,
                binary,
                deseadas.clone(),
                tiene_reglas,
            ));
        }
        errores
    }

    /// Los pares `(uid, binary)` distintos que tienen pids enrolados por dominio
    /// ahora mismo. El barrido periódico de TTL los recorre para recalcular sus
    /// IPs deseadas y bajar las vencidas.
    pub fn pares_dominio(&self) -> Vec<(u32, String)> {
        let mut pares: Vec<(u32, String)> = self
            .dominio
            .values()
            .map(|d| (d.uid, d.binary.clone()))
            .collect();
        pares.sort();
        pares.dedup();
        pares
    }

    /// Lleva lo marcado a coincidir con `deseados` (`pid → uid` que deberían
    /// estar cortados): marca los que faltan y limpia los que sobran. Es el
    /// barrido inicial de `/proc` al arrancar (nada marcado aún → marca todos) y
    /// la resincronización cuando el usuario cambia el switch de una app.
    ///
    /// Devuelve los errores que hubo, sin cortar: un pid que no se pudo marcar no
    /// debe impedir marcar los demás. El llamador los registra ruidoso.
    pub fn reconciliar(&mut self, deseados: &HashMap<u32, u32>) -> Vec<String> {
        let mut errores = Vec::new();
        for (&pid, &uid) in deseados {
            if !self.marcados.contains_key(&pid) {
                if let Err(e) = self.bloquear(uid, pid) {
                    errores.push(e);
                }
            }
        }
        let sobrantes: Vec<u32> = self
            .marcados
            .keys()
            .copied()
            .filter(|pid| !deseados.contains_key(pid))
            .collect();
        for pid in sobrantes {
            if let Err(e) = self.limpiar(pid) {
                errores.push(e);
            }
        }
        errores
    }

    /// Cuántos pids hay marcados ahora mismo. Para las pruebas y el diagnóstico.
    #[cfg(test)]
    pub fn marcados(&self) -> usize {
        self.marcados.len()
    }
}

/// La clave del mapa: `(uid << 32 | pid)`. **Tiene que ser idéntica** a la que
/// calcula el programa BPF; está acá como función con prueba propia porque es el
/// punto exacto donde los dos lados se pueden desincronizar sin que nada avise.
fn clave(uid: u32, pid: u32) -> u64 {
    ((uid as u64) << 32) | (pid as u64)
}

/// Si un error de `quitar` es «la clave no estaba» —el caso que `unblock` trata
/// como éxito—.
///
/// En aya 0.14, `HashMap::remove` de una clave inexistente **no** devuelve
/// `MapError::KeyNotFound`: `remove` llama `bpf_map_delete_elem`, que con el
/// kernel contestando `ENOENT` se envuelve en
/// `MapError::SyscallError { io_error }` con `io_error` de clase `NotFound`. Un
/// `match` que sólo mirara `KeyNotFound` daría `Err` al desmarcar un pid ausente,
/// que es justo lo que `unblock` promete que no pasa. Se cubren las dos formas:
/// el `SyscallError`/`NotFound` que aya 0.14 produce de verdad, y `KeyNotFound`
/// por si una versión futura vuelve a él.
fn es_clave_ausente(error: &MapError) -> bool {
    match error {
        MapError::KeyNotFound => true,
        MapError::SyscallError(SyscallError { io_error, .. }) => {
            io_error.kind() == ErrorKind::NotFound
        }
        _ => false,
    }
}

/// Si un error de `insertar` es «el mapa está lleno» —el caso que obliga el
/// fail-closed de `block`—.
///
/// Un `BPF_MAP_TYPE_HASH` lleno hace que `bpf_map_update_elem` conteste `E2BIG`
/// (y algunos kernels `ENOSPC`), que aya envuelve en
/// `MapError::SyscallError { io_error }`. Se reconocen las dos para no tratar un
/// mapa lleno como un error cualquiera: cuando lo es, el corte no se aplicó.
fn es_mapa_lleno(error: &MapError) -> bool {
    match error {
        MapError::SyscallError(SyscallError { io_error, .. }) => {
            matches!(
                io_error.raw_os_error(),
                Some(libc::E2BIG) | Some(libc::ENOSPC)
            )
        }
        _ => false,
    }
}

/// Traduce un fallo de carga del objeto a algo accionable.
///
/// El modo más probable en producción es `EPERM` al llamar `bpf()`: la unidad
/// instala `SystemCallFilter=@system-service`, que **no** incluye `bpf`, así que
/// sin sumar `SystemCallFilter=bpf` la carga falla acá. Se nombra el síntoma
/// para que no se diagnostique como «kernel sin BPF».
/// La cadena de causas de un error, no sólo su `Display`. Aya oculta el errno en
/// el `Display` de `SyscallError`, y al diagnosticar por qué no cargó o no
/// escribió el cortafuegos el errno (EPERM, ENOENT…) es justo lo que hace falta.
fn con_causas(error: &dyn std::error::Error) -> String {
    let mut texto = error.to_string();
    let mut causa = error.source();
    while let Some(c) = causa {
        texto.push_str(&format!(": {c}"));
        causa = c.source();
    }
    texto
}

fn describir_carga(error: &str) -> String {
    format!(
        "no se pudo cargar el programa BPF del cortafuegos: {error}. \
         Si es EPERM, revisá que la unidad tenga «SystemCallFilter=bpf» además de \
         «@system-service», y que el proceso conserve CAP_BPF y CAP_NET_ADMIN"
    )
}

/// Traduce un fallo de `accion` («cargar» o «adjuntar») de un programa a algo
/// accionable.
fn describir_adjunto(nombre: &str, accion: &str, error: &str) -> String {
    format!(
        "no se pudo {accion} «{nombre}» en {CGROUP_RAIZ}: {error}. \
         Adjuntar cgroup/connect pide CAP_NET_ADMIN y un kernel con CONFIG_CGROUP_BPF"
    )
}

/// El motor real: dueño del programa BPF cargado, adjunta al cgroup y escribe el
/// mapa con syscalls `bpf()`.
///
/// Es el adapter fino sobre aya: I/O privilegiado puro que sólo sale bien como
/// root, sin más lógica que las propias syscalls. La lógica que se puede razonar
/// y probar sin privilegios vive en [`Firewall`] sobre [`MotorBpf`].
pub struct MotorAya {
    ebpf: Ebpf,
}

impl MotorAya {
    /// Carga el objeto commiteado en el kernel. No adjunta nada todavía: eso lo
    /// hace [`Firewall::con_motor`] a través de [`MotorBpf::adjuntar`].
    fn cargar() -> Result<Self, String> {
        // `include_bytes_aligned!` garantiza el alineamiento que el cargador de
        // aya exige; `include_bytes!` a secas puede quedar desalineado y fallar.
        let objeto = aya::include_bytes_aligned!("vasak-firewall.bpf.o");
        let ebpf = Ebpf::load(objeto).map_err(|e| describir_carga(&con_causas(&e)))?;
        Ok(Self { ebpf })
    }

    /// El mapa `BLOCKED` como vista escribible. Se toma por operación y no se
    /// guarda: `aya::maps::HashMap` toma prestado el `MapData` del `Ebpf`, y
    /// retenerlo chocaría con el préstamo mutable que necesita cada escritura.
    fn mapa(&mut self) -> Result<BpfHashMap<&mut aya::maps::MapData, u64, u8>, MapError> {
        let mapa = self
            .ebpf
            .map_mut(MAPA_BLOQUEADOS)
            .ok_or_else(|| MapError::InvalidName {
                name: MAPA_BLOQUEADOS.to_string(),
            })?;
        BpfHashMap::try_from(mapa)
    }

    /// El mapa `DOMAIN_BLOCKED` como vista escribible, tomado por operación por lo
    /// mismo que [`Self::mapa`]: el préstamo del `MapData` del `Ebpf` no se puede
    /// retener entre escrituras.
    fn mapa_dominio(
        &mut self,
    ) -> Result<BpfHashMap<&mut aya::maps::MapData, DomainKey, u8>, MapError> {
        let mapa = self
            .ebpf
            .map_mut(MAPA_DOMINIO)
            .ok_or_else(|| MapError::InvalidName {
                name: MAPA_DOMINIO.to_string(),
            })?;
        BpfHashMap::try_from(mapa)
    }

    /// Extrae el ring buffer `EVENTS` del objeto cargado. Sale del `Ebpf` con
    /// `take_map`: el mapa en vivo lo lee un task aparte y no vuelve a tocar este
    /// `Ebpf`, así que llevárselo evita compartir el `Ebpf` entre el enforcement y
    /// el lector.
    fn tomar_eventos(&mut self) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        let mapa = self.ebpf.take_map(crate::firewall::mapa::MAPA_EVENTOS)?;
        aya::maps::RingBuf::try_from(mapa).ok()
    }
}

impl MotorBpf for MotorAya {
    fn adjuntar(&mut self, nombre: &str) -> Result<(), String> {
        let programa: &mut CgroupSockAddr = self
            .ebpf
            .program_mut(nombre)
            .ok_or_else(|| format!("el objeto BPF no tiene el programa «{nombre}»"))?
            .try_into()
            .map_err(|e| format!("«{nombre}» no es un programa cgroup/connect: {e}"))?;

        programa
            .load()
            .map_err(|e| describir_adjunto(nombre, "cargar", &con_causas(&e)))?;

        // El cgroup raíz se abre como archivo; aya adjunta por su descriptor.
        let cgroup = std::fs::File::open(CGROUP_RAIZ)
            .map_err(|e| format!("no se pudo abrir {CGROUP_RAIZ} para adjuntar «{nombre}»: {e}"))?;

        // `Single`, no `AllowMultiple`, por una razón empírica: con `AllowMultiple`
        // aya adjunta por link (`bpf_link_create`), y este kernel (CachyOS 7.3.1)
        // lo rechaza para `cgroup/connect` con EINVAL —verificado como root, la
        // prueba de integración falla ahí—. `Single` usa el `BPF_PROG_ATTACH`
        // legacy, que el kernel sí acepta. El riesgo de co-inquilinos (que otro
        // adjunto quiera el gancho connect de la raíz y `Single` lo rechace) queda
        // como investigación futura si aparece; que ande el kill-switch manda.
        programa
            .attach(cgroup, CgroupAttachMode::Single)
            .map_err(|e| describir_adjunto(nombre, "adjuntar", &con_causas(&e)))?;

        Ok(())
    }

    fn insertar(&mut self, clave: u64, valor: u8) -> Result<(), MapError> {
        self.mapa()?.insert(clave, valor, 0)
    }

    fn quitar(&mut self, clave: u64) -> Result<(), MapError> {
        self.mapa()?.remove(&clave)
    }

    fn insertar_ip(&mut self, pid_key: u64, ip: [u8; 16]) -> Result<(), MapError> {
        self.mapa_dominio()?
            .insert(clave_dominio(pid_key, ip), DENY, 0)
    }

    fn quitar_ip(&mut self, pid_key: u64, ip: [u8; 16]) -> Result<(), MapError> {
        self.mapa_dominio()?.remove(&clave_dominio(pid_key, ip))
    }
}

/// Un motor de mentira para ejercitar la lógica de `Firewall` y de `Enforcer`
/// sin ser root ni cargar un programa BPF. Anota lo que se le pide y devuelve lo
/// que se le programó.
///
/// Vive a nivel de módulo (no dentro de `mod tests`) para que el submódulo
/// `enrolar` también pueda probar sus adapters con un cortafuegos de mentira.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MotorFalso {
    /// Programas que se le pidió adjuntar, en orden.
    pub(crate) adjuntados: Vec<String>,
    /// Si está, el programa con ese nombre falla al adjuntar con ese mensaje.
    pub(crate) falla_al_adjuntar: Option<(String, String)>,
    /// Lo escrito: `(clave, valor)` de cada `insertar`.
    pub(crate) insertados: Vec<(u64, u8)>,
    /// Lo quitado: cada `clave` de `quitar`.
    pub(crate) quitados: Vec<u64>,
    /// Si está, `insertar` falla con este error.
    pub(crate) falla_al_insertar: Option<MapError>,
    /// Si está, `quitar` falla con este error.
    pub(crate) falla_al_quitar: Option<MapError>,
    /// Lo escrito en `DOMAIN_BLOCKED`: `(clave de pid, IP)` de cada `insertar_ip`.
    pub(crate) insertados_ip: Vec<(u64, [u8; 16])>,
    /// Lo quitado de `DOMAIN_BLOCKED`: cada `(clave de pid, IP)` de `quitar_ip`.
    pub(crate) quitados_ip: Vec<(u64, [u8; 16])>,
    /// Si está, `insertar_ip` falla con este error (para el fail-closed del mapa
    /// de dominio lleno).
    pub(crate) falla_al_insertar_ip: Option<MapError>,
}

#[cfg(test)]
impl MotorBpf for MotorFalso {
    fn adjuntar(&mut self, nombre: &str) -> Result<(), String> {
        if let Some((cual, motivo)) = &self.falla_al_adjuntar {
            if cual == nombre {
                return Err(motivo.clone());
            }
        }
        self.adjuntados.push(nombre.to_string());
        Ok(())
    }

    fn insertar(&mut self, clave: u64, valor: u8) -> Result<(), MapError> {
        if let Some(e) = self.falla_al_insertar.take() {
            return Err(e);
        }
        self.insertados.push((clave, valor));
        Ok(())
    }

    fn quitar(&mut self, clave: u64) -> Result<(), MapError> {
        if let Some(e) = self.falla_al_quitar.take() {
            return Err(e);
        }
        self.quitados.push(clave);
        Ok(())
    }

    fn insertar_ip(&mut self, pid_key: u64, ip: [u8; 16]) -> Result<(), MapError> {
        if let Some(e) = self.falla_al_insertar_ip.take() {
            return Err(e);
        }
        self.insertados_ip.push((pid_key, ip));
        Ok(())
    }

    fn quitar_ip(&mut self, pid_key: u64, ip: [u8; 16]) -> Result<(), MapError> {
        self.quitados_ip.push((pid_key, ip));
        Ok(())
    }
}

/// El cortafuegos de mentira listo para `Enforcer`, para las pruebas de los dos
/// módulos.
#[cfg(test)]
pub(crate) fn enforcer_falso() -> Enforcer<MotorFalso> {
    Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).expect("adjuntar con el falso"))
}

#[cfg(test)]
impl<M: MotorBpf> Enforcer<M> {
    /// El motor de mentira por dentro, para que las pruebas lean lo que se le
    /// pidió marcar o quitar.
    pub(crate) fn motor(&self) -> &M {
        &self.firewall.motor
    }

    /// Las IPs que un pid tiene cortadas por dominio ahora mismo, para las
    /// pruebas. `None` si el pid no está enrolado por dominio.
    pub(crate) fn ips_dominio(&self, pid: u32) -> Option<Vec<[u8; 16]>> {
        self.dominio.get(&pid).map(|d| {
            let mut v: Vec<[u8; 16]> = d.ips.iter().copied().collect();
            v.sort();
            v
        })
    }

    /// Cuántos pids hay enrolados por dominio.
    pub(crate) fn dominio_marcados(&self) -> usize {
        self.dominio.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Error as IoError;

    /// El `MapError` que aya 0.14 produce de verdad al quitar una clave ausente:
    /// `bpf_map_delete_elem` falla con `ENOENT`, que llega como `SyscallError`
    /// con un `io_error` de clase `NotFound`.
    fn error_clave_ausente() -> MapError {
        MapError::SyscallError(SyscallError {
            call: "bpf_map_delete_elem",
            io_error: IoError::from_raw_os_error(libc::ENOENT),
        })
    }

    /// El `MapError` de un mapa lleno: `bpf_map_update_elem` falla con `E2BIG`.
    fn error_mapa_lleno() -> MapError {
        MapError::SyscallError(SyscallError {
            call: "bpf_map_update_elem",
            io_error: IoError::from_raw_os_error(libc::E2BIG),
        })
    }

    // ── Funciones puras ──────────────────────────────────────────────────────

    /// La clave tiene que ser exactamente la que calcula el programa BPF:
    /// `(uid << 32 | pid)`. Si un lado cambia, un pid marcado por el daemon no
    /// es el que el programa consulta, y el bloqueo no hace nada sin que nada
    /// falle. Los casos cubren el pid y el uid en los dos medios de la palabra.
    #[test]
    fn la_clave_pone_el_uid_arriba_y_el_pid_abajo() {
        assert_eq!(clave(0, 0), 0);
        assert_eq!(clave(0, 1), 1);
        assert_eq!(clave(1, 0), 1 << 32);
        assert_eq!(clave(1, 2), (1 << 32) | 2);
        // Valores máximos en cada mitad, sin pisarse.
        assert_eq!(clave(u32::MAX, u32::MAX), u64::MAX);
        assert_eq!(clave(0xABCD, 0x1234), 0x0000_ABCD_0000_1234);
    }

    /// El pid nunca se cuela en la mitad del uid ni al revés: dos procesos con el
    /// mismo pid en usuarios distintos dan claves distintas (el caso que el uid
    /// en la clave existe para cubrir en el enganche a la raíz).
    #[test]
    fn mismo_pid_distinto_usuario_da_claves_distintas() {
        assert_ne!(clave(1000, 4242), clave(1001, 4242));
    }

    /// `DENY` es el byte que el programa BPF interpreta como «cortar». Si se
    /// cambia acá sin cambiarlo allá, el daemon marcaría con un valor que el
    /// programa trata como «permitir», y el bloqueo quedaría inerte.
    #[test]
    fn el_valor_de_denegar_es_uno() {
        assert_eq!(DENY, 1);
    }

    /// El error que de verdad produce aya 0.14 al quitar una clave ausente
    /// (`SyscallError`/`NotFound`) se reconoce como ausente, igual que el
    /// `KeyNotFound` histórico. Un error de otra clase, no.
    #[test]
    fn reconoce_la_clave_ausente_en_las_dos_formas_y_no_otros_errores() {
        assert!(es_clave_ausente(&error_clave_ausente()));
        assert!(es_clave_ausente(&MapError::KeyNotFound));
        // Un `SyscallError` que no es «no existe» (p. ej. EPERM) es un error real.
        assert!(!es_clave_ausente(&MapError::SyscallError(SyscallError {
            call: "bpf_map_delete_elem",
            io_error: IoError::from_raw_os_error(libc::EPERM),
        })));
        // Y cualquier otra variante tampoco cuenta como ausente.
        assert!(!es_clave_ausente(&MapError::InvalidName {
            name: "BLOCKED".to_string()
        }));
    }

    /// Un mapa lleno (`E2BIG`/`ENOSPC`) se reconoce como tal y ninguna otra cosa:
    /// de eso depende que el fail-closed se registre ruidoso en vez de pasar como
    /// un error cualquiera.
    #[test]
    fn reconoce_el_mapa_lleno_y_no_otros_errores() {
        assert!(es_mapa_lleno(&error_mapa_lleno()));
        assert!(es_mapa_lleno(&MapError::SyscallError(SyscallError {
            call: "bpf_map_update_elem",
            io_error: IoError::from_raw_os_error(libc::ENOSPC),
        })));
        // Un error que no es «lleno» (p. ej. EPERM) no cuenta.
        assert!(!es_mapa_lleno(&MapError::SyscallError(SyscallError {
            call: "bpf_map_update_elem",
            io_error: IoError::from_raw_os_error(libc::EPERM),
        })));
        assert!(!es_mapa_lleno(&error_clave_ausente()));
    }

    /// `block` sobre el mapa lleno da un error que nombra el tope y dice que el
    /// corte NO se aplicó: el llamador necesita eso para registrarlo ruidoso.
    #[test]
    fn block_con_el_mapa_lleno_lo_dice_claro() {
        let motor = MotorFalso {
            falla_al_insertar: Some(error_mapa_lleno()),
            ..Default::default()
        };
        let mut fw = Firewall::con_motor(motor).unwrap();
        let err = fw
            .block(1000, 42)
            .expect_err("el mapa lleno tiene que dar Err");
        assert!(err.contains(&CAPACIDAD_BLOCKED.to_string()), "{err}");
        assert!(err.contains("NO se está aplicando"), "{err}");
    }

    /// El mensaje de un fallo de carga nombra la syscall `bpf` de la unidad y las
    /// capacidades: es lo que hace la diferencia entre diagnosticar «falta el
    /// permiso» y «el kernel no tiene BPF».
    #[test]
    fn el_error_de_carga_es_accionable() {
        let msg = describir_carga("EPERM (os error 1)");
        assert!(msg.contains("EPERM (os error 1)"));
        assert!(msg.contains("SystemCallFilter=bpf"));
        assert!(msg.contains("CAP_BPF") && msg.contains("CAP_NET_ADMIN"));
    }

    /// El mensaje de un fallo de adjuntar nombra la acción, el programa, el
    /// cgroup y la capacidad que falta.
    #[test]
    fn el_error_de_adjuntar_es_accionable() {
        let msg = describir_adjunto("connect4", "adjuntar", "EPERM (os error 1)");
        assert!(msg.contains("connect4"));
        assert!(msg.contains("adjuntar"));
        assert!(msg.contains(CGROUP_RAIZ));
        assert!(msg.contains("CAP_NET_ADMIN"));
    }

    // ── Flujo de adjuntar ────────────────────────────────────────────────────

    /// `con_motor` adjunta los dos programas, en orden, y envuelve el motor.
    #[test]
    fn con_motor_adjunta_connect4_y_connect6_en_orden() {
        let fw = Firewall::con_motor(MotorFalso::default())
            .expect("adjuntar los dos no debería fallar con el motor de mentira");
        assert_eq!(fw.motor.adjuntados, vec!["connect4", "connect6"]);
    }

    /// Si adjuntar el segundo programa falla, `con_motor` devuelve ese error y no
    /// un cortafuegos a medio adjuntar: falla cerrado.
    #[test]
    fn con_motor_propaga_el_error_de_adjuntar_y_falla_cerrado() {
        let motor = MotorFalso {
            falla_al_adjuntar: Some(("connect6".to_string(), "sin CAP_NET_ADMIN".to_string())),
            ..Default::default()
        };
        let err = Firewall::con_motor(motor)
            .map(drop)
            .expect_err("un fallo al adjuntar connect6 tiene que propagarse");
        assert!(err.contains("sin CAP_NET_ADMIN"));
    }

    // ── block / unblock ──────────────────────────────────────────────────────

    /// `block` escribe `(clave(uid, pid), DENY)` en el mapa.
    #[test]
    fn block_marca_la_clave_con_deny() {
        let mut fw = Firewall::con_motor(MotorFalso::default()).unwrap();
        fw.block(1000, 4242).expect("marcar no debería fallar");
        assert_eq!(fw.motor.insertados, vec![(clave(1000, 4242), DENY)]);
    }

    /// Un fallo de escritura del mapa llega como `Err` con el pid, el uid y el
    /// motivo: el mensaje accionable que el llamador necesita.
    #[test]
    fn block_devuelve_un_error_accionable_si_falla_la_escritura() {
        let motor = MotorFalso {
            falla_al_insertar: Some(MapError::InvalidName {
                name: "BLOCKED".to_string(),
            }),
            ..Default::default()
        };
        let mut fw = Firewall::con_motor(motor).unwrap();
        let err = fw
            .block(7, 99)
            .expect_err("una escritura fallida tiene que dar Err");
        assert!(err.contains("99") && err.contains("uid 7"));
    }

    /// `unblock` quita la clave del mapa en el caso normal.
    #[test]
    fn unblock_quita_la_clave() {
        let mut fw = Firewall::con_motor(MotorFalso::default()).unwrap();
        fw.unblock(1000, 4242).expect("desmarcar no debería fallar");
        assert_eq!(fw.motor.quitados, vec![clave(1000, 4242)]);
    }

    /// Desmarcar un pid ausente es éxito, no error: aya 0.14 devuelve
    /// `SyscallError`/`NotFound`, y `unblock` tiene que tratarlo como «ya estaba
    /// en el estado deseado». Sin esto, limpiar un pid que ya salió daría `Err`.
    #[test]
    fn unblock_de_una_clave_ausente_es_exito() {
        let motor = MotorFalso {
            falla_al_quitar: Some(error_clave_ausente()),
            ..Default::default()
        };
        let mut fw = Firewall::con_motor(motor).unwrap();
        fw.unblock(1000, 4242)
            .expect("desmarcar una clave ausente tiene que ser Ok");
    }

    /// Un error de `quitar` que no es «ausente» sí es un fallo, con mensaje
    /// accionable.
    #[test]
    fn unblock_devuelve_error_ante_un_fallo_real() {
        let motor = MotorFalso {
            falla_al_quitar: Some(MapError::SyscallError(SyscallError {
                call: "bpf_map_delete_elem",
                io_error: IoError::from_raw_os_error(libc::EPERM),
            })),
            ..Default::default()
        };
        let mut fw = Firewall::con_motor(motor).unwrap();
        let err = fw
            .unblock(7, 99)
            .expect_err("un fallo real al quitar tiene que dar Err");
        assert!(err.contains("99") && err.contains("uid 7"));
    }

    // ── Enforcer: contabilidad de pids marcados y reconciliación ──────────────

    /// `bloquear` escribe el mapa y anota el pid como marcado; `limpiar` lo
    /// desmarca usando el uid anotado —que es lo único que queda cuando el
    /// proceso ya salió—.
    #[test]
    fn el_enforcer_marca_y_limpia_recordando_el_uid() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        e.bloquear(1000, 42).expect("marcar");
        assert_eq!(e.marcados(), 1);
        assert_eq!(e.firewall.motor.insertados, vec![(clave(1000, 42), DENY)]);

        // Limpiar sin pasar el uid: lo reconstruye de lo anotado.
        e.limpiar(42).expect("limpiar");
        assert_eq!(e.marcados(), 0);
        assert_eq!(e.firewall.motor.quitados, vec![clave(1000, 42)]);
    }

    /// Limpiar un pid que no teníamos marcado no hace nada (ni toca el mapa): un
    /// `exit` de un proceso que nunca cortamos no es un error.
    #[test]
    fn limpiar_lo_no_marcado_no_hace_nada() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        e.limpiar(42).expect("no es error");
        assert!(e.firewall.motor.quitados.is_empty());
    }

    /// Fail-closed: si la escritura del mapa falla, el pid **no** queda anotado
    /// como marcado —no se finge que el corte está aplicado— y el error sube.
    #[test]
    fn el_enforcer_no_anota_lo_que_no_pudo_marcar() {
        let motor = MotorFalso {
            falla_al_insertar: Some(error_mapa_lleno()),
            ..Default::default()
        };
        let mut e = Enforcer::nuevo(Firewall::con_motor(motor).unwrap());
        assert!(e.bloquear(1000, 42).is_err());
        assert_eq!(
            e.marcados(),
            0,
            "un pid que no se pudo cortar no puede figurar como cortado"
        );
    }

    /// `reconciliar` marca los que faltan y limpia los que sobran, llevando lo
    /// marcado a coincidir con lo deseado. Es el barrido inicial y la
    /// resincronización al cambiar el switch.
    #[test]
    fn reconciliar_marca_los_que_faltan_y_limpia_los_que_sobran() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());

        // Barrido inicial: nada marcado, se piden dos.
        let mut deseados = HashMap::new();
        deseados.insert(42u32, 1000u32);
        deseados.insert(43u32, 1000u32);
        assert!(e.reconciliar(&deseados).is_empty());
        assert_eq!(e.marcados(), 2);

        // Ahora se quita el switch de uno y aparece otro: 42 se limpia, 44 entra.
        let mut deseados2 = HashMap::new();
        deseados2.insert(43u32, 1000u32);
        deseados2.insert(44u32, 1001u32);
        assert!(e.reconciliar(&deseados2).is_empty());
        assert_eq!(e.marcados(), 2);
        assert_eq!(
            e.firewall.motor.quitados,
            vec![clave(1000, 42)],
            "sólo el que salió del conjunto se limpia"
        );
    }

    /// Un pid que no se pudo marcar en la reconciliación no corta la operación:
    /// se junta el error y se siguen marcando los demás.
    #[test]
    fn reconciliar_junta_errores_y_no_corta() {
        let motor = MotorFalso {
            falla_al_insertar: Some(error_mapa_lleno()),
            ..Default::default()
        };
        let mut e = Enforcer::nuevo(Firewall::con_motor(motor).unwrap());
        let mut deseados = HashMap::new();
        deseados.insert(42u32, 1000u32);
        deseados.insert(43u32, 1000u32);
        let errores = e.reconciliar(&deseados);
        // El primer insert falla (MotorFalso falla una vez), el segundo entra.
        assert_eq!(errores.len(), 1);
        assert_eq!(e.marcados(), 1);
    }

    // ── Enforcer: bloqueo por dominio (M2) ────────────────────────────────────

    /// Una IP v4 en los 16 bytes del mapa: octetos en los primeros 4, cero el
    /// resto, como arma el programa BPF para `connect4`.
    fn ip16(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        let mut v = [0u8; 16];
        v[0] = a;
        v[1] = b;
        v[2] = c;
        v[3] = d;
        v
    }

    fn set(ips: &[[u8; 16]]) -> HashSet<[u8; 16]> {
        ips.iter().copied().collect()
    }

    /// Enrolar un pid por dominio escribe `(clave de pid, IP)` en el mapa por cada
    /// IP deseada, con la clave `(uid << 32 | pid)` —la misma de M0—, y lo anota.
    #[test]
    fn reconciliar_dominio_pid_corta_las_ips_deseadas() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        let a = ip16(192, 0, 2, 1);
        let b = ip16(192, 0, 2, 2);

        assert!(e
            .reconciliar_dominio_pid(1000, 42, "/usr/bin/vasak-mail", set(&[a, b]), true)
            .is_empty());
        assert_eq!(e.dominio_marcados(), 1);
        assert_eq!(e.ips_dominio(42), Some(vec![a, b]));

        let pid_key = clave(1000, 42);
        let mut escritas = e.motor().insertados_ip.clone();
        escritas.sort();
        assert_eq!(escritas, vec![(pid_key, a), (pid_key, b)]);
    }

    /// Un segundo reconcile con un conjunto distinto agrega lo nuevo y quita lo
    /// que salió —el `reconcile` lleva el pid al estado deseado—.
    #[test]
    fn reconciliar_dominio_pid_agrega_y_quita_la_diferencia() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        let a = ip16(192, 0, 2, 1);
        let b = ip16(192, 0, 2, 2);
        let c = ip16(192, 0, 2, 3);
        e.reconciliar_dominio_pid(1000, 42, "/app", set(&[a, b]), true);
        e.reconciliar_dominio_pid(1000, 42, "/app", set(&[b, c]), true);

        assert_eq!(e.ips_dominio(42), Some(vec![b, c]));
        let pid_key = clave(1000, 42);
        assert_eq!(
            e.motor().quitados_ip,
            vec![(pid_key, a)],
            "sólo la que salió"
        );
        // b no se reescribió (ya estaba): sólo a y b en el primer paso, c en el segundo.
        assert!(e.motor().insertados_ip.contains(&(pid_key, c)));
        assert_eq!(
            e.motor()
                .insertados_ip
                .iter()
                .filter(|(_, ip)| *ip == b)
                .count(),
            1,
            "una IP que ya estaba no se reescribe"
        );
    }

    /// Reconciliar a un conjunto vacío un pid enrolado lo limpia entero: quita sus
    /// IPs y lo saca del enrolado. Es lo que pasa al borrar la regla de dominio.
    #[test]
    fn reconciliar_dominio_pid_a_vacio_limpia_el_pid() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        let a = ip16(192, 0, 2, 1);
        e.reconciliar_dominio_pid(1000, 42, "/app", set(&[a]), true);
        assert_eq!(e.dominio_marcados(), 1);

        assert!(e
            .reconciliar_dominio_pid(1000, 42, "/app", HashSet::new(), false)
            .is_empty());
        assert_eq!(e.dominio_marcados(), 0);
        assert_eq!(e.ips_dominio(42), None);
        assert_eq!(e.motor().quitados_ip, vec![(clave(1000, 42), a)]);
    }

    /// Un pid sin enrolar y sin IPs deseadas no toca el mapa: la gran mayoría de
    /// los `exec`/`fork` (binarios sin regla de dominio) pasa por acá sin costo.
    #[test]
    fn reconciliar_dominio_pid_sin_reglas_ni_enrolar_no_hace_nada() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        assert!(e
            .reconciliar_dominio_pid(1000, 42, "/app", HashSet::new(), false)
            .is_empty());
        assert_eq!(e.dominio_marcados(), 0);
        assert!(e.motor().insertados_ip.is_empty());
        assert!(e.motor().quitados_ip.is_empty());
    }

    /// Un binario con regla pero todavía sin IPs resueltas **enrola** el pid con un
    /// conjunto vacío: hace falta para que el empujón del snoop lo alcance después.
    #[test]
    fn reconciliar_dominio_pid_con_reglas_pero_sin_ips_enrola_vacio() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        assert!(e
            .reconciliar_dominio_pid(1000, 42, "/app", HashSet::new(), true)
            .is_empty());
        assert_eq!(
            e.dominio_marcados(),
            1,
            "queda enrolado aunque no corte nada"
        );
        assert_eq!(e.ips_dominio(42), Some(vec![]));
        assert!(e.motor().insertados_ip.is_empty(), "no escribió ninguna IP");
    }

    /// Fail-closed: si el mapa de dominio está lleno, la IP que no se pudo escribir
    /// **no** queda anotada como cortada —no se finge el corte— y el error sube.
    #[test]
    fn reconciliar_dominio_pid_fail_closed_no_anota_lo_que_no_pudo_cortar() {
        let motor = MotorFalso {
            falla_al_insertar_ip: Some(error_mapa_lleno()),
            ..Default::default()
        };
        let mut e = Enforcer::nuevo(Firewall::con_motor(motor).unwrap());
        let a = ip16(192, 0, 2, 1);
        let b = ip16(192, 0, 2, 2);
        // La primera inserción falla (MotorFalso falla una vez), la segunda entra.
        let errores = e.reconciliar_dominio_pid(1000, 42, "/app", set(&[a, b]), true);
        assert_eq!(errores.len(), 1);
        assert!(
            errores[0].contains("DOMAIN_BLOCKED está lleno"),
            "{}",
            errores[0]
        );
        // Sólo una de las dos quedó anotada: la que sí se pudo escribir.
        assert_eq!(e.ips_dominio(42).map(|v| v.len()), Some(1));
    }

    /// Limpiar un pid enrolado por dominio (su `exit`) quita sus IPs del mapa y lo
    /// saca del enrolado, aunque no tuviera kill-switch de M0.
    #[test]
    fn limpiar_un_pid_de_dominio_quita_sus_ips() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        let a = ip16(192, 0, 2, 1);
        e.reconciliar_dominio_pid(1000, 42, "/app", set(&[a]), true);
        e.limpiar(42).expect("limpiar");
        assert_eq!(e.dominio_marcados(), 0);
        assert_eq!(e.motor().quitados_ip, vec![(clave(1000, 42), a)]);
    }

    /// Reconciliar por binario alcanza a todos los pids vivos de ese `(uid, binary)`
    /// —lo que corre cuando el snoop ata una IP nueva al dominio—.
    #[test]
    fn reconciliar_dominio_binario_alcanza_a_todos_los_pids_del_binario() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        let a = ip16(192, 0, 2, 1);
        // Dos pids del mismo binario, uno de otro.
        e.reconciliar_dominio_pid(1000, 42, "/app", set(&[a]), true);
        e.reconciliar_dominio_pid(1000, 43, "/app", set(&[a]), true);
        e.reconciliar_dominio_pid(1000, 99, "/otro", set(&[a]), true);

        let b = ip16(192, 0, 2, 2);
        e.reconciliar_dominio_binario(1000, "/app", set(&[a, b]), true);
        // Los dos pids de /app ganan b; el de /otro no.
        assert_eq!(e.ips_dominio(42), Some(vec![a, b]));
        assert_eq!(e.ips_dominio(43), Some(vec![a, b]));
        assert_eq!(e.ips_dominio(99), Some(vec![a]));
    }

    /// `pares_dominio` da los `(uid, binary)` distintos con pids enrolados, para el
    /// barrido de TTL.
    #[test]
    fn pares_dominio_da_los_binarios_distintos_enrolados() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        let a = ip16(192, 0, 2, 1);
        e.reconciliar_dominio_pid(1000, 42, "/app", set(&[a]), true);
        e.reconciliar_dominio_pid(1000, 43, "/app", set(&[a]), true);
        e.reconciliar_dominio_pid(1001, 50, "/app", set(&[a]), true);
        assert_eq!(
            e.pares_dominio(),
            vec![(1000, "/app".to_string()), (1001, "/app".to_string())]
        );
    }

    /// El kill-switch de M0 y el bloqueo por dominio conviven sobre el mismo pid y
    /// se limpian juntos al salir, sin pisarse: son dos mapas distintos.
    #[test]
    fn m0_y_dominio_conviven_y_se_limpian_juntos() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        let a = ip16(192, 0, 2, 1);
        e.bloquear(1000, 42).expect("M0");
        e.reconciliar_dominio_pid(1000, 42, "/app", set(&[a]), true);
        assert_eq!(e.marcados(), 1);
        assert_eq!(e.dominio_marcados(), 1);

        e.limpiar(42).expect("limpiar");
        assert_eq!(e.marcados(), 0);
        assert_eq!(e.dominio_marcados(), 0);
        assert_eq!(e.motor().quitados, vec![clave(1000, 42)], "M0 limpio");
        assert_eq!(
            e.motor().quitados_ip,
            vec![(clave(1000, 42), a)],
            "dominio limpio"
        );
    }

    /// Granularidad por binario: la clave lleva el pid, así que lo cortado para un
    /// pid no alcanza a otro del mismo uid. Un pid de otro binario (sin regla) ni
    /// se enrola ni recibe entradas, y reconciliar «por binario» no toca sus pids.
    #[test]
    fn la_ip_cortada_para_un_pid_no_alcanza_a_otro_del_mismo_uid() {
        let mut e = Enforcer::nuevo(Firewall::con_motor(MotorFalso::default()).unwrap());
        let a = ip16(192, 0, 2, 1);
        e.reconciliar_dominio_pid(1000, 42, "/app", set(&[a]), true);
        // Otro pid del mismo uid, de un binario sin regla: no recibe nada.
        e.reconciliar_dominio_pid(1000, 43, "/otro", HashSet::new(), false);
        e.reconciliar_dominio_binario(1000, "/app", set(&[a]), true);

        assert_eq!(e.ips_dominio(43), None, "el pid ajeno no se enrola");
        assert_eq!(
            e.motor().insertados_ip,
            vec![(clave(1000, 42), a)],
            "sólo la clave del pid con la regla; ninguna del otro pid"
        );
        assert_ne!(clave(1000, 42), clave(1000, 43));
    }

    /// La `DomainKey` que escribe el daemon tiene el layout que lee el programa BPF:
    /// el pid de M0 en el offset 0 y la IP en el 8, 24 bytes en total.
    #[test]
    fn la_clave_de_dominio_lleva_el_pid_y_la_ip_en_su_sitio() {
        let k = clave_dominio(clave(1000, 42), ip16(192, 0, 2, 1));
        assert_eq!(std::mem::offset_of!(DomainKey, pid_key), 0);
        assert_eq!(std::mem::offset_of!(DomainKey, ip), 8);
        // SAFETY: `DomainKey` es `repr(C)` y Copy; se leen sus 24 bytes como crudos.
        let bytes: [u8; 24] = unsafe { std::mem::transmute(k) };
        assert_eq!(bytes[..8], clave(1000, 42).to_ne_bytes());
        assert_eq!(bytes[8..12], [192, 0, 2, 1]);
        assert_eq!(bytes[12..], [0u8; 12]);
    }

    /// Fail-closed completo: la IP que no entró al mapa no se anota, y el próximo
    /// reconcile la **reintenta** en vez de darla por cortada.
    #[test]
    fn la_ip_que_no_entro_al_mapa_se_reintenta_en_el_siguiente_reconcile() {
        let motor = MotorFalso {
            falla_al_insertar_ip: Some(error_mapa_lleno()),
            ..Default::default()
        };
        let mut e = Enforcer::nuevo(Firewall::con_motor(motor).unwrap());
        let a = ip16(192, 0, 2, 1);
        assert_eq!(
            e.reconciliar_dominio_pid(1000, 42, "/app", set(&[a]), true)
                .len(),
            1
        );
        assert_eq!(e.ips_dominio(42), Some(vec![]), "no se anotó como cortada");
        assert!(e.motor().insertados_ip.is_empty());

        assert!(e
            .reconciliar_dominio_pid(1000, 42, "/app", set(&[a]), true)
            .is_empty());
        assert_eq!(e.ips_dominio(42), Some(vec![a]));
        assert_eq!(e.motor().insertados_ip, vec![(clave(1000, 42), a)]);
    }

    /// El error de mapa lleno de `bloquear_ip` sube con el mensaje accionable; uno
    /// que no es de mapa lleno no lo menciona.
    #[test]
    fn bloquear_ip_con_el_mapa_lleno_devuelve_error_accionable() {
        let motor = MotorFalso {
            falla_al_insertar_ip: Some(error_mapa_lleno()),
            ..Default::default()
        };
        let mut fw = Firewall::con_motor(motor).unwrap();
        let err = fw
            .bloquear_ip(clave(1000, 42), ip16(192, 0, 2, 1))
            .expect_err("tiene que fallar");
        assert!(err.contains("192.0.2.1"), "{err}");
        assert!(err.contains("DOMAIN_BLOCKED está lleno"), "{err}");
        assert!(err.contains("NO se está aplicando"), "{err}");
    }

    /// Aditivo: en el programa BPF el veredicto es el OR del kill-switch de M0 y del
    /// match por dominio, y el kill-switch sigue saliendo de `BLOCKED` con la misma
    /// clave. Sin reglas `DOMAIN_BLOCKED` está vacío y el OR vale lo que M0.
    #[test]
    fn la_fuente_bpf_combina_m0_y_dominio_con_un_or() {
        let fuente = include_str!("../../../firewall-ebpf/src/main.rs");
        assert!(
            fuente.contains("let bloqueado = kill_switch || dominio_bloqueado;"),
            "el veredicto dejó de ser kill_switch OR dominio"
        );
        assert!(
            fuente.contains("BLOCKED.get(&key)"),
            "el kill-switch de M0 ya no consulta BLOCKED por la clave de pid"
        );
        assert!(
            fuente.contains("DOMAIN_BLOCKED.get(&domain_key)")
                && fuente.contains("pid_key: key,")
                && fuente.contains("ip: dst,"),
            "el match por dominio tiene que usar la clave de pid y el destino del connect"
        );
    }

    /// Los dos lados se desincronizan sin aviso si alguien toca uno solo. Esta
    /// prueba lee la fuente del programa BPF (siempre disponible, a diferencia del
    /// toolchain BPF que necesita la correspondencia del objeto) y exige que la
    /// derivación de la clave y el valor `DENY` sean los de este módulo.
    #[test]
    fn la_fuente_bpf_deriva_la_misma_clave_y_el_mismo_deny() {
        let fuente = include_str!("../../../firewall-ebpf/src/main.rs");
        assert!(
            fuente.contains("let key = ((uid as u64) << 32) | (tgid as u64);"),
            "el programa BPF cambió la derivación de la clave: ya no es (uid << 32 | tgid)"
        );
        assert!(
            fuente.contains(&format!("const DENY: u8 = {DENY};")),
            "el programa BPF y el daemon discrepan en el valor de DENY"
        );
        assert!(
            fuente.contains(&format!("static {MAPA_BLOQUEADOS}: HashMap<u64, u8>")),
            "el mapa del programa BPF ya no se llama «{MAPA_BLOQUEADOS}» o cambió de tipo"
        );
        assert!(
            fuente.contains(&format!("with_max_entries({CAPACIDAD_BLOCKED},")),
            "el tope del mapa BPF y CAPACIDAD_BLOCKED discrepan; el fail-closed \
             del mapa lleno dejaría de corresponder al tope real"
        );
    }

    /// La clave y el mapa del bloqueo por dominio tienen que ser los mismos de los
    /// dos lados: si el programa BPF cambia la forma de `DomainKey` o el nombre/tope
    /// del mapa y el daemon no, el daemon escribiría una clave que el programa no
    /// consulta y el bloqueo por dominio quedaría inerte sin que nada falle.
    #[test]
    fn la_fuente_bpf_define_la_misma_clave_de_dominio_y_el_mismo_mapa() {
        let fuente = include_str!("../../../firewall-ebpf/src/main.rs");
        assert!(
            fuente.contains("struct DomainKey {"),
            "el programa BPF ya no define DomainKey"
        );
        for campo in ["pid_key: u64,", "ip: [u8; 16],"] {
            assert!(
                fuente.contains(campo),
                "DomainKey del programa BPF ya no tiene «{campo}»; se desincronizó del daemon"
            );
        }
        // El orden importa tanto como los campos: `pid_key` antes de `ip`.
        let cuerpo = fuente
            .split("struct DomainKey {")
            .nth(1)
            .and_then(|r| r.split("\n}").next())
            .expect("falta el cuerpo de DomainKey");
        assert!(
            cuerpo.find("pid_key").unwrap_or(usize::MAX) < cuerpo.find("ip:").unwrap_or(0),
            "el orden de DomainKey cambió"
        );
        assert!(
            fuente.contains(&format!("static {MAPA_DOMINIO}: HashMap<DomainKey, u8>")),
            "el mapa del bloqueo por dominio ya no se llama «{MAPA_DOMINIO}» o cambió de tipo"
        );
        assert!(
            fuente.contains(&format!("with_max_entries({CAPACIDAD_DOMINIO},")),
            "el tope de DOMAIN_BLOCKED y CAPACIDAD_DOMINIO discrepan"
        );
        // Y los dos lados miden lo mismo: 24 bytes (u64 + [u8;16], repr(C)).
        assert_eq!(std::mem::size_of::<DomainKey>(), 24);
    }

    /// Sin privilegios la carga no puede salir bien, y tiene que decirlo con un
    /// `Err` accionable en vez de dar un cortafuegos que no filtra nada. Con root
    /// la carga sí puede salir, y eso lo cubre la prueba de integración.
    #[test]
    fn sin_privilegios_la_carga_falla_cerrada_y_con_motivo() {
        // SAFETY: `geteuid` no tiene precondiciones y no falla.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let Err(motivo) = Firewall::load() else {
            panic!("la carga salió bien sin privilegios: el cortafuegos no puede estar activo");
        };
        assert!(
            motivo.contains("CAP_NET_ADMIN"),
            "el error no es accionable (no nombra la capacidad que falta): {motivo}"
        );
    }
}
