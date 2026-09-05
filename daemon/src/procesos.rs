//! Una caché de pid → ruta del ejecutable, para poder nombrar a un programa que
//! ya se cerró.
//!
//! # Por qué hace falta
//!
//! El vigilante del registro del kernel resuelve qué aplicación fue leyendo
//! `/proc/<pid>/exe`. Eso funciona sólo si el proceso sigue vivo cuando llega
//! la denegación — y muchas veces no lo está, **precisamente porque se le negó
//! lo que necesitaba**: un programa al que le cortan la cámara suele salir en
//! el acto.
//!
//! El resultado era que el caso más común se perdía: no se avisaba, no se
//! anotaba, y la aplicación no aparecía nunca en la lista de permisos, así que
//! no había forma de concederle nada. Un bloqueo definitivo por omisión.
//!
//! # De dónde salen los datos
//!
//! Del conector de procesos del kernel (`CONFIG_PROC_EVENTS`), que avisa por
//! netlink de cada `exec` **en el momento en que ocurre**. Ahí el proceso sí
//! existe, así que su ruta se puede leer y guardar. Cuando después llega una
//! denegación de un pid que ya no está, la ruta sale de acá.
//!
//! Se guarda sólo lo que puede llegar a interesar —los ejecutables bajo el
//! directorio de alguien, que es lo que los perfiles confinan— para que la
//! caché no crezca con cada comando que se corre en el sistema.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cuánto se recuerda un proceso después de su `exec`.
///
/// La denegación llega en milisegundos, así que con poco alcanza. Un minuto es
/// holgado y acota el tamaño: los pid se reciclan, y recordar uno viejo sería
/// peor que no recordar nada — nombraría a la aplicación equivocada.
const MEMORIA: Duration = Duration::from_secs(60);

/// Techo de entradas, por si el sistema hace muchos `exec` de golpe.
const MAXIMO: usize = 512;

pub type Cache = Arc<Mutex<HashMap<u32, (PathBuf, Instant)>>>;

pub fn cache_nueva() -> Cache {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Si vale la pena recordar este ejecutable.
///
/// Sólo los que están bajo el directorio de una persona: son los que los
/// perfiles confinan, y los únicos para los que una excepción tiene sentido.
/// Recordar `/usr/bin/ls` llenaría la caché sin que nunca sirva.
pub fn interesa(ruta: &std::path::Path) -> bool {
    ruta.starts_with("/home/") || ruta.starts_with("/root/")
}

/// Anota un proceso, si interesa.
pub fn anotar(cache: &Cache, pid: u32) {
    let Ok(ruta) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
        return; // ya no está, o no es nuestro
    };
    if !interesa(&ruta) {
        return;
    }
    let ahora = Instant::now();
    let Ok(mut mapa) = cache.lock() else { return };
    mapa.retain(|_, (_, cuando)| ahora.duration_since(*cuando) < MEMORIA);
    if mapa.len() >= MAXIMO {
        return;
    }
    mapa.insert(pid, (ruta, ahora));
}

/// La ruta de un proceso que ya no está, si se la recuerda.
pub fn recordada(cache: &Cache, pid: u32) -> Option<PathBuf> {
    let ahora = Instant::now();
    let mapa = cache.lock().ok()?;
    mapa.get(&pid)
        .filter(|(_, cuando)| ahora.duration_since(*cuando) < MEMORIA)
        .map(|(ruta, _)| ruta.clone())
}

// ── El conector de procesos ─────────────────────────────────────────────────

const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const NLMSG_DONE: u16 = 3;

/// Dónde empieza el evento dentro de lo que llega por el socket.
///
/// Son tres encabezados pegados: `nlmsghdr` (16), `cn_msg` (20) y después el
/// `proc_event`, cuyos primeros 16 bytes son el tipo, la CPU y la marca de
/// tiempo. El pid del `exec` viene justo después.
const OFFSET_QUE: usize = 16 + 20;
const OFFSET_PID: usize = OFFSET_QUE + 16;

/// Saca el pid de un mensaje del conector, si es un `exec`.
///
/// Separado del socket para poder comprobarlo sin privilegios ni kernel: es
/// aritmética de desplazamientos, que es justo donde uno se equivoca.
pub fn pid_de_exec(mensaje: &[u8]) -> Option<u32> {
    if mensaje.len() < OFFSET_PID + 4 {
        return None;
    }
    let que = u32::from_ne_bytes(mensaje[OFFSET_QUE..OFFSET_QUE + 4].try_into().ok()?);
    if que != PROC_EVENT_EXEC {
        return None;
    }
    let pid = i32::from_ne_bytes(mensaje[OFFSET_PID..OFFSET_PID + 4].try_into().ok()?);
    u32::try_from(pid).ok()
}

/// El mensaje que le pide al kernel que empiece a avisar.
fn suscripcion(pid_propio: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(OFFSET_QUE + 4);
    // nlmsghdr
    m.extend_from_slice(&((OFFSET_QUE + 4) as u32).to_ne_bytes());
    m.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
    m.extend_from_slice(&0u16.to_ne_bytes()); // flags
    m.extend_from_slice(&0u32.to_ne_bytes()); // seq
    m.extend_from_slice(&pid_propio.to_ne_bytes());
    // cn_msg
    m.extend_from_slice(&CN_IDX_PROC.to_ne_bytes());
    m.extend_from_slice(&CN_VAL_PROC.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes()); // seq
    m.extend_from_slice(&0u32.to_ne_bytes()); // ack
    m.extend_from_slice(&4u16.to_ne_bytes()); // len
    m.extend_from_slice(&0u16.to_ne_bytes()); // flags
    // datos
    m.extend_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
    m
}

/// Escucha los `exec` del sistema y va llenando la caché.
///
/// Nunca termina; se lanza en un hilo propio. Si el conector no está
/// disponible se registra y se sale: sin caché el vigilante sigue funcionando,
/// sólo que pierde a los procesos que mueren rápido — que es exactamente como
/// estaba antes.
pub fn escuchar(cache: Cache) {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_CONNECTOR,
        )
    };
    if fd < 0 {
        tracing::info!(
            "No se pudo abrir el conector de procesos ({}); \
             no se van a poder nombrar los programas que se cierren enseguida",
            std::io::Error::last_os_error()
        );
        return;
    }

    let mut direccion: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    direccion.nl_family = libc::AF_NETLINK as u16;
    direccion.nl_groups = CN_IDX_PROC;
    let enlazado = unsafe {
        libc::bind(
            fd,
            &direccion as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if enlazado < 0 {
        tracing::warn!(
            "No se pudo escuchar el conector de procesos: {}",
            std::io::Error::last_os_error()
        );
        unsafe { libc::close(fd) };
        return;
    }

    let mensaje = suscripcion(std::process::id());
    let enviado = unsafe {
        libc::send(fd, mensaje.as_ptr() as *const libc::c_void, mensaje.len(), 0)
    };
    if enviado < 0 {
        tracing::warn!(
            "No se pudo pedir los avisos de proceso: {}",
            std::io::Error::last_os_error()
        );
        unsafe { libc::close(fd) };
        return;
    }

    tracing::info!("Escuchando los arranques de proceso del kernel");
    let mut buffer = [0u8; 1024];
    loop {
        let leidos = unsafe {
            libc::recv(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0)
        };
        if leidos <= 0 {
            // EINTR y demás: reintentar. Un error persistente haría girar esto,
            // así que se corta.
            if leidos < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            tracing::warn!("El conector de procesos se cerró; ya no se recuerdan rutas");
            unsafe { libc::close(fd) };
            return;
        }
        if let Some(pid) = pid_de_exec(&buffer[..leidos as usize]) {
            anotar(&cache, pid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arma un mensaje como el que manda el kernel.
    fn mensaje(que: u32, pid: i32) -> Vec<u8> {
        let mut m = vec![0u8; OFFSET_PID + 4];
        m[OFFSET_QUE..OFFSET_QUE + 4].copy_from_slice(&que.to_ne_bytes());
        m[OFFSET_PID..OFFSET_PID + 4].copy_from_slice(&pid.to_ne_bytes());
        m
    }

    #[test]
    fn de_un_exec_sale_el_pid() {
        assert_eq!(pid_de_exec(&mensaje(PROC_EVENT_EXEC, 4242)), Some(4242));
    }

    /// Por el conector pasan también forks, salidas y cambios de uid. Tomar el
    /// pid de cualquiera de ellos llenaría la caché de basura.
    #[test]
    fn los_otros_eventos_se_ignoran() {
        for que in [0x0000_0001, 0x0000_0004, 0x8000_0000] {
            assert_eq!(pid_de_exec(&mensaje(que, 4242)), None, "aceptó el evento {que:#x}");
        }
    }

    #[test]
    fn un_mensaje_corto_no_lee_de_mas() {
        assert_eq!(pid_de_exec(&[]), None);
        assert_eq!(pid_de_exec(&[0u8; 40]), None);
        assert_eq!(pid_de_exec(&mensaje(PROC_EVENT_EXEC, 1)[..OFFSET_PID + 3]), None);
    }

    #[test]
    fn la_suscripcion_tiene_la_forma_que_el_kernel_espera() {
        let m = suscripcion(1234);
        assert_eq!(m.len(), OFFSET_QUE + 4);
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()), m.len() as u32);
        assert_eq!(
            u32::from_ne_bytes(m[OFFSET_QUE..OFFSET_QUE + 4].try_into().unwrap()),
            PROC_CN_MCAST_LISTEN
        );
    }

    /// Recordar todo el sistema sería inútil y caro: los perfiles sólo confinan
    /// lo que está en el directorio de alguien.
    #[test]
    fn solo_interesan_los_ejecutables_de_las_personas() {
        assert!(interesa(std::path::Path::new("/home/x/Apps/a.AppImage")));
        assert!(interesa(std::path::Path::new("/root/a.AppImage")));
        assert!(!interesa(std::path::Path::new("/usr/bin/ls")));
        assert!(!interesa(std::path::Path::new("/tmp/a")));
    }

    #[test]
    fn lo_que_no_se_anoto_no_se_recuerda() {
        let cache = cache_nueva();
        assert_eq!(recordada(&cache, 999), None);
    }

    /// Los pid se reciclan. Recordar uno viejo nombraría a la aplicación
    /// equivocada, que es peor que no recordar nada.
    #[test]
    fn una_entrada_vencida_no_se_devuelve() {
        let cache = cache_nueva();
        let viejo = Instant::now() - MEMORIA - Duration::from_secs(1);
        cache
            .lock()
            .unwrap()
            .insert(7, (PathBuf::from("/home/x/a.AppImage"), viejo));
        assert_eq!(recordada(&cache, 7), None);
    }
}
