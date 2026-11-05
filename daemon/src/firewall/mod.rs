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

use aya::maps::HashMap as BpfHashMap;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::{Ebpf, EbpfError};

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

/// El cortafuegos cargado: es dueño del programa BPF y de su mapa. Mientras vive,
/// los programas siguen adjuntos; al soltarlo, se desadjuntan.
pub struct Firewall {
    ebpf: Ebpf,
}

impl Firewall {
    /// Carga el objeto commiteado y adjunta `connect4`/`connect6` al cgroup raíz.
    ///
    /// El objeto se embebe en el binario con `include_bytes_aligned!`: no hay un
    /// `.o` que ubicar en runtime, coherente con el daemon de un solo binario, y
    /// el build estable no necesita nightly ni `bpf-linker` para producirlo.
    pub fn load() -> Result<Self, String> {
        // `include_bytes_aligned!` garantiza el alineamiento que el cargador de
        // aya exige; `include_bytes!` a secas puede quedar desalineado y fallar.
        let objeto = aya::include_bytes_aligned!("vasak-firewall.bpf.o");
        let mut ebpf = Ebpf::load(objeto).map_err(describir_carga)?;

        adjuntar(&mut ebpf, "connect4")?;
        adjuntar(&mut ebpf, "connect6")?;

        tracing::info!(
            "Cortafuegos por aplicación cargado y adjunto a {CGROUP_RAIZ} (connect4/connect6)"
        );
        Ok(Self { ebpf })
    }

    /// Marca un pid como bloqueado: a partir de ahora el programa corta sus
    /// `connect()`. Idempotente (reescribe la misma clave).
    pub fn block(&mut self, uid: u32, pid: u32) -> Result<(), String> {
        let mut mapa = self.mapa()?;
        mapa.insert(clave(uid, pid), DENY, 0)
            .map_err(|e| format!("no se pudo marcar el pid {pid} (uid {uid}): {e}"))
    }

    /// Desmarca un pid: sus `connect()` vuelven a pasar. No es error desmarcar uno
    /// que no estaba (el proceso pudo salir y ya haberse limpiado).
    pub fn unblock(&mut self, uid: u32, pid: u32) -> Result<(), String> {
        let mut mapa = self.mapa()?;
        match mapa.remove(&clave(uid, pid)) {
            Ok(()) => Ok(()),
            // `KeyNotFound` no es un fallo: desmarcar lo que ya no está es llegar
            // al mismo estado deseado.
            Err(aya::maps::MapError::KeyNotFound) => Ok(()),
            Err(e) => Err(format!(
                "no se pudo desmarcar el pid {pid} (uid {uid}): {e}"
            )),
        }
    }

    /// El mapa `BLOCKED` como vista escribible. Se toma por operación y no se
    /// guarda: `aya::maps::HashMap` toma prestado el `MapData` del `Ebpf`, y
    /// retenerlo chocaría con el préstamo mutable que necesita cada escritura.
    fn mapa(&mut self) -> Result<BpfHashMap<&mut aya::maps::MapData, u64, u8>, String> {
        let mapa = self
            .ebpf
            .map_mut(MAPA_BLOQUEADOS)
            .ok_or_else(|| format!("el objeto BPF no tiene el mapa «{MAPA_BLOQUEADOS}»"))?;
        BpfHashMap::try_from(mapa)
            .map_err(|e| format!("«{MAPA_BLOQUEADOS}» no es un HashMap como se esperaba: {e}"))
    }
}

/// La clave del mapa: `(uid << 32 | pid)`. **Tiene que ser idéntica** a la que
/// calcula el programa BPF; está acá como función con prueba propia porque es el
/// punto exacto donde los dos lados se pueden desincronizar sin que nada avise.
fn clave(uid: u32, pid: u32) -> u64 {
    ((uid as u64) << 32) | (pid as u64)
}

/// Carga y adjunta uno de los dos programas al cgroup raíz.
fn adjuntar(ebpf: &mut Ebpf, nombre: &str) -> Result<(), String> {
    let programa: &mut CgroupSockAddr = ebpf
        .program_mut(nombre)
        .ok_or_else(|| format!("el objeto BPF no tiene el programa «{nombre}»"))?
        .try_into()
        .map_err(|e| format!("«{nombre}» no es un programa cgroup/connect: {e}"))?;

    programa
        .load()
        .map_err(|e| describir_adjunto(nombre, "cargar", e))?;

    // El cgroup raíz se abre como archivo; aya adjunta por su descriptor.
    let cgroup = std::fs::File::open(CGROUP_RAIZ)
        .map_err(|e| format!("no se pudo abrir {CGROUP_RAIZ} para adjuntar «{nombre}»: {e}"))?;

    programa
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|e| describir_adjunto(nombre, "adjuntar", e))?;

    Ok(())
}

/// Traduce un fallo de carga del objeto a algo accionable.
///
/// El modo más probable en producción es `EPERM` al llamar `bpf()`: la unidad
/// instala `SystemCallFilter=@system-service`, que **no** incluye `bpf`, así que
/// sin sumar `SystemCallFilter=bpf` la carga falla acá. Se nombra el síntoma
/// para que no se diagnostique como «kernel sin BPF».
fn describir_carga(error: EbpfError) -> String {
    format!(
        "no se pudo cargar el programa BPF del cortafuegos: {error}. \
         Si es EPERM, revisá que la unidad tenga «SystemCallFilter=bpf» además de \
         «@system-service», y que el proceso conserve CAP_BPF y CAP_NET_ADMIN"
    )
}

fn describir_adjunto(nombre: &str, accion: &str, error: aya::programs::ProgramError) -> String {
    format!(
        "no se pudo {accion} «{nombre}» en {CGROUP_RAIZ}: {error}. \
         Adjuntar cgroup/connect pide CAP_NET_ADMIN y un kernel con CONFIG_CGROUP_BPF"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// programa trata como «permitir», y el kill-switch quedaría inerte.
    #[test]
    fn el_valor_de_denegar_es_uno() {
        assert_eq!(DENY, 1);
    }
}
