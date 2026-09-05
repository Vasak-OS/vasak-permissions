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
use std::time::Duration;

/// Cuánto se recuerda un proceso después de su `exec`.
///
/// La denegación llega en milisegundos, así que con poco alcanza. Un minuto es
/// holgado y acota el tamaño: los pid se reciclan, y recordar uno viejo sería
/// peor que no recordar nada — nombraría a la aplicación equivocada.
const MEMORIA: Duration = Duration::from_secs(60);

/// Techo de entradas, por si el sistema hace muchos `exec` de golpe.
const MAXIMO: usize = 512;

/// Varias generaciones por pid, cada una con el momento de su `exec`.
///
/// No alcanza con guardar una ruta por pid. Los pid se reciclan: si al proceso
/// A se le niega algo, termina, el número pasa a B y B arranca antes de que se
/// procese la línea del registro, una caché de una sola ruta devolvería a B —y
/// la decisión, y la excepción que se escriba después, irían sobre la
/// aplicación equivocada—.
///
/// Con las generaciones y la hora de la denegación se puede elegir la correcta:
/// la última que arrancó **antes** de que ocurriera el bloqueo.
pub type Cache = Arc<Mutex<HashMap<u32, Vec<(PathBuf, Duration)>>>>;

/// Cuántos arranques se recuerdan por pid.
const GENERACIONES: usize = 4;

/// Cuándo arrancó de verdad ese proceso, en segundos desde el epoch.
///
/// No es lo mismo que «cuándo nos enteramos». Entre el `exec` y el momento en
/// que este proceso lee el aviso del conector pasa un rato —el planificador, la
/// cola de netlink, el `read_link` de `/proc`— y esa demora se sumaba a la hora
/// guardada. Si por culpa de ella la generación correcta quedaba anotada
/// *después* del bloqueo, `recordada` la descartaba y caía en la generación
/// anterior del mismo pid: otro programa, y sobre ese nombre se escribe una
/// excepción de AppArmor. El error que la demora podía causar es justo el que
/// esta caché existe para evitar.
///
/// El campo 22 de `/proc/<pid>/stat` es el arranque en tics desde el encendido.
/// Junto con el pid forma la identidad que el kernel considera única: dos
/// procesos con el mismo número se distinguen por ahí. Sumado a `btime` da una
/// hora comparable con la que trae el registro de auditoría, exacta al tic.
fn arranque_de(pid: u32) -> Option<Duration> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;

    // El campo 2 es el nombre del ejecutable entre paréntesis, y puede contener
    // espacios y paréntesis: partir por espacios desde el principio da
    // cualquier cosa. Se corta después del **último** `)`, que es el cierre.
    let resto = &stat[stat.rfind(')')? + 1..];

    // Ahí empieza el campo 3, así que el 22 queda en la posición 19.
    let tics: u64 = resto.split_whitespace().nth(19)?.parse().ok()?;

    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz <= 0 {
        return None;
    }
    let hz = hz as u64;

    Some(btime()? + Duration::new(tics / hz, ((tics % hz) * 1_000_000_000 / hz) as u32))
}

/// Cuándo se encendió la máquina, según `/proc/stat`. No cambia mientras
/// corre, así que se lee una sola vez.
fn btime() -> Option<Duration> {
    static BTIME: std::sync::OnceLock<Option<Duration>> = std::sync::OnceLock::new();
    *BTIME.get_or_init(|| {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let linea = stat.lines().find(|l| l.starts_with("btime "))?;
        Some(Duration::from_secs(linea.split_whitespace().nth(1)?.parse().ok()?))
    })
}

/// El momento actual, en segundos desde el epoch, para poder compararlo con la
/// marca de tiempo que trae el registro del kernel.
fn ahora_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

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
    // El arranque real si se puede leer; si el proceso ya se fue entre el aviso
    // y esta lectura, la hora de ahora, que es lo mejor que queda.
    let ahora = ahora_epoch();
    let arranco = arranque_de(pid).unwrap_or(ahora);
    let Ok(mut mapa) = cache.lock() else { return };
    mapa.retain(|_, generaciones| {
        generaciones.retain(|(_, cuando)| ahora.saturating_sub(*cuando) < MEMORIA);
        !generaciones.is_empty()
    });
    if mapa.len() >= MAXIMO && !mapa.contains_key(&pid) {
        return;
    }
    let generaciones = mapa.entry(pid).or_default();
    generaciones.push((ruta, arranco));
    if generaciones.len() > GENERACIONES {
        generaciones.remove(0);
    }
}

/// La ruta que tenía ese pid cuando ocurrió el bloqueo.
///
/// `cuando` es la marca de tiempo que trae el propio registro del kernel. Se
/// elige la última generación que arrancó **antes o en** ese momento: una
/// posterior es otro proceso que heredó el número, y devolverla nombraría a la
/// aplicación equivocada.
///
/// Si no hay ninguna anterior, no se devuelve nada. Preferimos no nombrar a
/// nadie antes que nombrar mal: sobre ese nombre se anota una decisión y se
/// escribe una excepción.
pub fn recordada(cache: &Cache, pid: u32, cuando: Duration) -> Option<PathBuf> {
    let mapa = cache.lock().ok()?;
    mapa.get(&pid)?
        .iter()
        .filter(|(_, arranco)| *arranco <= cuando)
        .filter(|(_, arranco)| cuando.saturating_sub(*arranco) < MEMORIA)
        .max_by_key(|(_, arranco)| *arranco)
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

/// Saca el pid de un mensaje del conector, si es un `exec` nuestro.
///
/// Separado del socket para poder comprobarlo sin privilegios ni kernel: es
/// aritmética de desplazamientos, que es justo donde uno se equivoca.
///
/// Comprueba también el identificador del conector. Sin eso, cualquier mensaje
/// con los bytes en la posición correcta pasaría por un `exec`, incluidos los
/// de otro subsistema que comparta el socket.
pub fn pid_de_exec(mensaje: &[u8]) -> Option<u32> {
    if mensaje.len() < OFFSET_PID + 4 {
        return None;
    }
    // El `cn_msg` empieza después del `nlmsghdr` y arranca con su `cb_id`.
    let idx = u32::from_ne_bytes(mensaje[16..20].try_into().ok()?);
    let val = u32::from_ne_bytes(mensaje[20..24].try_into().ok()?);
    if idx != CN_IDX_PROC || val != CN_VAL_PROC {
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
        // `recvmsg` y no `recv`, para quedarse con la dirección de quien envía.
        //
        // Un socket de netlink también recibe mensajes de **otros procesos del
        // usuario** que conozcan nuestro identificador de puerto. Sin mirar el
        // remitente, cualquiera podría fabricar un `exec` falso y envenenar la
        // caché: la denegación siguiente quedaría atribuida a la ruta que él
        // eligiera, y sobre esa ruta se anotaría una decisión y se escribiría
        // una excepción. Los mensajes del kernel llegan con `nl_pid` en cero.
        let mut remitente: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        };
        let mut cabecera: libc::msghdr = unsafe { std::mem::zeroed() };
        cabecera.msg_name = &mut remitente as *mut _ as *mut libc::c_void;
        cabecera.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        cabecera.msg_iov = &mut iov;
        cabecera.msg_iovlen = 1;

        let leidos = unsafe { libc::recvmsg(fd, &mut cabecera, 0) };
        if leidos > 0 {
            // Truncado: no se puede confiar en lo que quedó, y procesarlo a
            // medias sería leer campos de otro mensaje.
            if cabecera.msg_flags & libc::MSG_TRUNC != 0 {
                continue;
            }
            if remitente.nl_pid != 0 {
                tracing::debug!(
                    "Mensaje de proceso descartado: no vino del kernel (nl_pid={})",
                    remitente.nl_pid
                );
                continue;
            }
        }
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
        // El identificador del conector, que ahora también se comprueba.
        m[16..20].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
        m[20..24].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
        m[OFFSET_QUE..OFFSET_QUE + 4].copy_from_slice(&que.to_ne_bytes());
        m[OFFSET_PID..OFFSET_PID + 4].copy_from_slice(&pid.to_ne_bytes());
        m
    }

    /// La hora que se guarda tiene que ser la del `exec`, no la de la lectura.
    /// Contra el propio proceso de la prueba: arrancó recién, y antes que
    /// ahora. Si esto devolviera la hora de lectura, la diferencia con `ahora`
    /// sería cero y la demora que se quiso sacar seguiría ahí.
    #[test]
    fn el_arranque_es_el_del_proceso_y_no_el_de_la_lectura() {
        let mio = arranque_de(std::process::id()).expect("nuestro propio /proc/<pid>/stat");
        let ahora = ahora_epoch();
        assert!(mio <= ahora, "arranque {mio:?} después de ahora {ahora:?}");
        assert!(
            ahora - mio < Duration::from_secs(600),
            "el proceso de la prueba no puede llevar diez minutos corriendo"
        );
    }

    /// Y contra init, cuyo arranque se conoce por otra vía: `/proc/uptime`.
    /// Dos caminos distintos hasta el mismo número; si el campo 22 estuviera
    /// mal contado, o los tics mal convertidos, no coincidirían.
    #[test]
    fn el_arranque_de_init_coincide_con_el_uptime() {
        let Some(init) = arranque_de(1) else { return };
        let Ok(texto) = std::fs::read_to_string("/proc/uptime") else { return };
        let Some(segundos) = texto.split_whitespace().next() else { return };
        let Ok(uptime) = segundos.parse::<f64>() else { return };

        let edad = (ahora_epoch() - init).as_secs_f64();
        assert!(
            (edad - uptime).abs() < 5.0,
            "init lleva {edad:.0}s según /proc/<pid>/stat y {uptime:.0}s según uptime"
        );
    }

    /// Un pid que no existe no debe hacer nada raro: `anotar` ya lo descarta
    /// antes, pero la conversión se llama con lo que venga del kernel.
    #[test]
    fn un_pid_inexistente_no_tiene_arranque() {
        assert_eq!(arranque_de(u32::MAX), None);
    }

    #[test]
    fn de_un_exec_sale_el_pid() {
        assert_eq!(pid_de_exec(&mensaje(PROC_EVENT_EXEC, 4242)), Some(4242));
    }

    /// Un mensaje de otro subsistema del conector no es un arranque de proceso,
    /// aunque tenga los bytes en la posición correcta.
    #[test]
    fn un_mensaje_de_otro_subsistema_se_ignora() {
        let mut m = mensaje(PROC_EVENT_EXEC, 4242);
        m[16..20].copy_from_slice(&99u32.to_ne_bytes());
        assert_eq!(pid_de_exec(&m), None);
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

    fn en(segundos: u64) -> Duration {
        Duration::from_secs(1_788_000_000 + segundos)
    }

    fn con(pid: u32, generaciones: &[(&str, u64)]) -> Cache {
        let cache = cache_nueva();
        cache.lock().unwrap().insert(
            pid,
            generaciones
                .iter()
                .map(|(r, s)| (PathBuf::from(*r), en(*s)))
                .collect(),
        );
        cache
    }

    #[test]
    fn lo_que_no_se_anoto_no_se_recuerda() {
        assert_eq!(recordada(&cache_nueva(), 999, en(10)), None);
    }

    #[test]
    fn se_devuelve_la_generacion_que_estaba_corriendo() {
        let cache = con(7, &[("/home/x/a.AppImage", 10)]);
        assert_eq!(
            recordada(&cache, 7, en(11)),
            Some(PathBuf::from("/home/x/a.AppImage"))
        );
    }

    /// El caso que motiva las generaciones: el pid 7 fue de A, A terminó, el
    /// número pasó a B, y recién después se procesa el bloqueo **de A**.
    /// Devolver B haría que la decisión y la excepción fueran sobre la
    /// aplicación equivocada.
    #[test]
    fn un_pid_reciclado_no_nombra_a_la_aplicacion_nueva() {
        let cache = con(7, &[("/home/x/vieja.AppImage", 10), ("/home/x/nueva.AppImage", 20)]);
        assert_eq!(
            recordada(&cache, 7, en(15)),
            Some(PathBuf::from("/home/x/vieja.AppImage")),
            "eligió una generación posterior al bloqueo"
        );
    }

    /// Y si el bloqueo es anterior a todo lo que se recuerda, no se nombra a
    /// nadie: preferimos no decir nada antes que decir mal.
    #[test]
    fn sin_generacion_anterior_no_se_devuelve_nada() {
        let cache = con(7, &[("/home/x/nueva.AppImage", 20)]);
        assert_eq!(recordada(&cache, 7, en(15)), None);
    }

    #[test]
    fn una_generacion_vencida_no_se_devuelve() {
        let cache = con(7, &[("/home/x/a.AppImage", 10)]);
        assert_eq!(recordada(&cache, 7, en(10 + MEMORIA.as_secs() + 1)), None);
    }
}
