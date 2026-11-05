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

pub mod enrolar;

use std::collections::HashMap;
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

/// Los dos programas `cgroup/connect` que se adjuntan a la raíz, en orden.
const PROGRAMAS: [&str; 2] = ["connect4", "connect6"];

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
    /// `pid → uid` de los que tenemos marcados ahora mismo.
    marcados: HashMap<u32, u32>,
}

impl<M: MotorBpf> Enforcer<M> {
    pub fn nuevo(firewall: Firewall<M>) -> Self {
        Self {
            firewall,
            marcados: HashMap::new(),
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
    pub fn limpiar(&mut self, pid: u32) -> Result<(), String> {
        if let Some(uid) = self.marcados.remove(&pid) {
            self.firewall.unblock(uid, pid)?;
        }
        Ok(())
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
