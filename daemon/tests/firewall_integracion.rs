//! El programa BPF, cargado de verdad, corta lo que tiene que cortar.
//!
//! Las pruebas unitarias del módulo `firewall` comprueban la clave del mapa
//! contra sí misma; eso no prueba que el objeto commiteado cargue, se adjunte al
//! cgroup y efectivamente deniegue un `connect()`. Esto sí: carga el objeto,
//! adjunta `connect4`, marca el propio pid y verifica que su `connect()` falla
//! con `EPERM`; lo desmarca y verifica que vuelve a pasar.
//!
//! Necesita privilegios (`bpf()` para cargar el programa, `CAP_NET_ADMIN` para
//! adjuntarlo al cgroup) y un kernel con `CONFIG_CGROUP_BPF`. Se **salta** —no
//! falla— cuando no corre como root, que es el caso del CI del taller: un salteo
//! determinista y marcado no debe hundir la cobertura.
//!
//! El crate del daemon es un binario, así que esta prueba de integración no
//! puede importar el módulo `firewall`: carga el mismo objeto commiteado con aya
//! directamente, lo que además ejercita el objeto de punta a punta.

use aya::maps::{HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::Ebpf;

const CGROUP_RAIZ: &str = "/sys/fs/cgroup";
const DENY: u8 = 1;
/// Los bits del valor de `FORCE_RESOLVER`, iguales al daemon y al programa BPF.
const FORCE_DNS: u8 = 1;
const FORCE_DOH: u8 = 2;
/// El tamaño del `ConnectionEvent` del programa (32 bytes con relleno explícito);
/// el parser del daemon usa los mismos desplazamientos.
const EVENTO_LEN: usize = 32;

/// La clave de `DOMAIN_BLOCKED`, igual que en el daemon y el programa BPF:
/// `(uid << 32 | pid)` más la IP de destino en 16 bytes. `repr(C)` + `Pod` para
/// que aya la escriba como clave cruda.
#[repr(C)]
#[derive(Clone, Copy)]
struct DomainKey {
    pid_key: u64,
    ip: [u8; 16],
}

// SAFETY: `repr(C)`, `Copy`, sin punteros: cualquier secuencia de bytes de su
// tamaño es válida, que es lo que `aya::Pod` exige.
unsafe impl aya::Pod for DomainKey {}

/// La clave de 16 bytes de `SYSTEM_RESOLVERS`/`KNOWN_DOH`, igual que en el daemon:
/// aya no implementa `Pod` para arreglos, así que hace falta el envoltorio.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Ip16([u8; 16]);

// SAFETY: `repr(transparent)` sobre `[u8; 16]`, `Copy`, sin punteros.
unsafe impl aya::Pod for Ip16 {}

/// La IPv4 en los 16 bytes del mapa, como la arma `connect4`: octetos primero,
/// cero el resto.
fn ip16(ip: [u8; 4]) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[..4].copy_from_slice(&ip);
    v
}

/// El objeto commiteado, el mismo que embebe el daemon. `include_bytes_aligned!`
/// (no `include_bytes!`): el parser de aya exige el ELF alineado, y los bytes de
/// un `include_bytes!` a secas pueden quedar desalineados y hacer fallar la carga.
static OBJETO: &[u8] = aya::include_bytes_aligned!("../src/firewall/vasak-firewall.bpf.o");

fn es_root() -> bool {
    // SAFETY: `geteuid` no tiene precondiciones y no falla.
    unsafe { libc::geteuid() == 0 }
}

/// La clave del mapa, igual que en el daemon y en el programa BPF.
fn clave(uid: u32, pid: u32) -> u64 {
    ((uid as u64) << 32) | (pid as u64)
}

/// Intenta un `connect()` IPv4 no bloqueante a TEST-NET-1 (192.0.2.1, no rutea)
/// y devuelve el `errno` resultante (0 si no hubo error inmediato).
///
/// Con el programa cortando, `connect()` devuelve `EPERM` en el acto. Sin cortar
/// y no bloqueante, devuelve `EINPROGRESS` u otro, nunca `EPERM`: ese es el
/// discriminante.
fn errno_de_connect() -> i32 {
    errno_de_connect_a([192, 0, 2, 1])
}

/// Igual, pero a una IP de destino cualquiera (dentro de TEST-NET, que no rutea),
/// para distinguir qué destino corta el bloqueo por dominio y cuál no.
fn errno_de_connect_a(ip: [u8; 4]) -> i32 {
    errno_de_connect_puerto(ip, 80)
}

/// Igual, a una IP y **puerto** cualesquiera: lo usa el forzado del resolvedor, que
/// decide por puerto (53/853/443). No bloqueante, así que sin cortar devuelve
/// `EINPROGRESS`/`ECONNREFUSED`, nunca `EPERM`: ese es el discriminante.
fn errno_de_connect_puerto(ip: [u8; 4], puerto: u16) -> i32 {
    // SAFETY: llamadas a la API de sockets de POSIX con argumentos válidos; el
    // descriptor se cierra antes de salir.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return *libc::__errno_location();
        }
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = puerto.to_be();
        addr.sin_addr.s_addr = u32::from_be_bytes(ip).to_be();
        let r = libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let err = if r == 0 { 0 } else { *libc::__errno_location() };
        libc::close(fd);
        err
    }
}

#[test]
fn un_pid_marcado_no_conecta_y_uno_sin_marcar_si() {
    if !es_root() {
        eprintln!("la prueba de integración del cortafuegos necesita root; se salta");
        return;
    }

    let mut ebpf = Ebpf::load(OBJETO).expect("no se pudo cargar el objeto BPF");

    // El ring buffer del mapa en vivo (M1): se saca del Ebpf antes de adjuntar,
    // igual que hace el daemon, para drenar los eventos que emiten los connect.
    let mut eventos: RingBuf<MapData> =
        RingBuf::try_from(ebpf.take_map("EVENTS").expect("falta el mapa EVENTS"))
            .expect("EVENTS no es un ring buffer");

    let programa: &mut CgroupSockAddr = ebpf
        .program_mut("connect4")
        .expect("falta connect4")
        .try_into()
        .expect("connect4 no es cgroup/connect");
    programa.load().expect("no se pudo cargar connect4");
    let cgroup = std::fs::File::open(CGROUP_RAIZ).expect("no se pudo abrir el cgroup raíz");
    // `Single`, no `AllowMultiple`: con `AllowMultiple` aya adjunta por link
    // (`bpf_link_create`), que este kernel (CachyOS 7.3.1) rechaza para
    // `cgroup/connect` con EINVAL. `Single` usa el `BPF_PROG_ATTACH` legacy, que
    // el kernel sí acepta —verificado como root—.
    programa
        .attach(cgroup, CgroupAttachMode::Single)
        .expect("no se pudo adjuntar connect4 al cgroup raíz");

    let uid = unsafe { libc::geteuid() };
    // El tgid del proceso, que es lo que lee el programa BPF (`pid_tgid >> 32`).
    let pid = std::process::id();
    let key = clave(uid, pid);

    // Sin marcar: el connect no debe ser denegado por el programa.
    assert_ne!(
        errno_de_connect(),
        libc::EPERM,
        "un pid sin marcar no debería recibir EPERM"
    );

    {
        let mapa = ebpf.map_mut("BLOCKED").expect("falta el mapa BLOCKED");
        let mut blocked: BpfHashMap<_, u64, u8> =
            BpfHashMap::try_from(mapa).expect("BLOCKED no es un HashMap");
        blocked
            .insert(key, DENY, 0)
            .expect("no se pudo marcar el pid");
    }

    // Marcado: el connect tiene que ser cortado con EPERM.
    assert_eq!(
        errno_de_connect(),
        libc::EPERM,
        "un pid marcado debería recibir EPERM al conectar"
    );

    {
        let mapa = ebpf.map_mut("BLOCKED").expect("falta el mapa BLOCKED");
        let mut blocked: BpfHashMap<_, u64, u8> =
            BpfHashMap::try_from(mapa).expect("BLOCKED no es un HashMap");
        blocked.remove(&key).expect("no se pudo desmarcar el pid");
    }

    // Desmarcado: vuelve a pasar.
    assert_ne!(
        errno_de_connect(),
        libc::EPERM,
        "un pid desmarcado no debería seguir recibiendo EPERM"
    );

    // El mapa en vivo (M1): los connect de arriba —permitidos y bloqueado—
    // tuvieron que dejar eventos en el ring. Se drena y se busca el del connect
    // marcado: puerto 80, TCP, veredicto DENY, y el uid/pid de la prueba. El
    // ringbuf es síncrono, así que ya están todos tras los connect.
    let mut vio_bloqueado_al_80 = false;
    let mut vio_algun_evento = false;
    while let Some(item) = eventos.next() {
        assert!(item.len() >= EVENTO_LEN, "evento más corto que el struct");
        vio_algun_evento = true;
        let ev_uid = u32::from_le_bytes(item[0..4].try_into().unwrap());
        let ev_tgid = u32::from_le_bytes(item[4..8].try_into().unwrap());
        let ip = [item[8], item[9], item[10], item[11]];
        let ev_port = u16::from_le_bytes(item[24..26].try_into().unwrap());
        let ev_family = item[26];
        let ev_proto = item[27];
        let ev_verdict = item[28];
        if ev_verdict == DENY {
            assert_eq!(ev_uid, uid, "el evento clava el uid real");
            assert_eq!(ev_tgid, pid, "y el tgid del que conectó");
            assert_eq!(ev_port, 80, "el puerto de destino en orden de host");
            assert_eq!(ev_family, 2, "AF_INET para el connect4");
            assert_eq!(ev_proto, 6, "IPPROTO_TCP");
            assert_eq!(ip, [192, 0, 2, 1], "la IP de destino tal cual");
            vio_bloqueado_al_80 = true;
        }
    }
    assert!(vio_algun_evento, "no llegó ningún evento al ring buffer");
    assert!(
        vio_bloqueado_al_80,
        "no se observó el connect bloqueado al 192.0.2.1:80 en el mapa en vivo"
    );

    // ── Bloqueo por dominio (M2): corte por (clave de pid, IP) ────────────────
    //
    // El daemon mete una `(clave de pid, IP)` en `DOMAIN_BLOCKED` por una regla de
    // dominio (resuelve el dominio a esa IP desde el snoop). El programa corta el
    // `connect()` de **ese** pid a **esa** IP, y a nada más. Acá se escribe el mapa
    // a mano —como lo haría el daemon tras resolver el dominio— y se comprueba la
    // granularidad por binario: la regla de otra app (otro pid) del mismo uid no
    // alcanza a este proceso. El kill-switch de M0 ya se quitó arriba, así que lo
    // único que puede cortar es la regla de dominio.
    let ip_bloqueada = [192, 0, 2, 50];
    let ip_libre = [192, 0, 2, 51];
    let ip_de_otro = [192, 0, 2, 52];
    let otro_pid = pid.wrapping_add(1);
    {
        let mapa = ebpf
            .map_mut("DOMAIN_BLOCKED")
            .expect("falta el mapa DOMAIN_BLOCKED");
        let mut dominio: BpfHashMap<_, DomainKey, u8> =
            BpfHashMap::try_from(mapa).expect("DOMAIN_BLOCKED no es un HashMap");
        // La IP del dominio bloqueado, para ESTE pid.
        dominio
            .insert(
                DomainKey {
                    pid_key: key,
                    ip: ip16(ip_bloqueada),
                },
                DENY,
                0,
            )
            .expect("no se pudo marcar la IP del dominio");
        // La misma clase de regla, pero anotada contra OTRO pid (otra app del mismo
        // uid): no debe alcanzar a este proceso.
        dominio
            .insert(
                DomainKey {
                    pid_key: clave(uid, otro_pid),
                    ip: ip16(ip_de_otro),
                },
                DENY,
                0,
            )
            .expect("no se pudo marcar la IP de otro pid");
    }

    assert_eq!(
        errno_de_connect_a(ip_bloqueada),
        libc::EPERM,
        "el connect de un pid enrolado a la IP de su dominio bloqueado tiene que cortarse"
    );
    assert_ne!(
        errno_de_connect_a(ip_libre),
        libc::EPERM,
        "una IP sin regla no se corta: sólo la del dominio bloqueado"
    );
    // El corazón de la granularidad por binario: la IP cortada para OTRO pid NO
    // corta a este, aunque compartan uid.
    assert_ne!(
        errno_de_connect_a(ip_de_otro),
        libc::EPERM,
        "la regla de otra app (otro pid) del mismo uid no puede alcanzar a este proceso"
    );

    // Al quitar la regla, la IP vuelve a pasar.
    {
        let mapa = ebpf
            .map_mut("DOMAIN_BLOCKED")
            .expect("falta el mapa DOMAIN_BLOCKED");
        let mut dominio: BpfHashMap<_, DomainKey, u8> =
            BpfHashMap::try_from(mapa).expect("DOMAIN_BLOCKED no es un HashMap");
        dominio
            .remove(&DomainKey {
                pid_key: key,
                ip: ip16(ip_bloqueada),
            })
            .expect("no se pudo desmarcar la IP del dominio");
    }
    assert_ne!(
        errno_de_connect_a(ip_bloqueada),
        libc::EPERM,
        "tras quitar la regla de dominio, la IP vuelve a pasar"
    );

    // ── Forzar el resolvedor del sistema (M2, PR-C) ───────────────────────────
    //
    // El daemon marca `FORCE_RESOLVER[clave de pid] = FORCE_DNS|FORCE_DOH` para los
    // pids de binarios con regla de dominio, puebla `SYSTEM_RESOLVERS` con los
    // resolvedores del sistema y `KNOWN_DOH` con las IPs DoH conocidas. Acá se
    // escriben a mano y se comprueba el corte por puerto. El kill-switch de M0 y el
    // bloqueo por dominio ya se quitaron, así que lo único que puede cortar es el
    // forzado del resolvedor.
    let resolvedor = [127u8, 0, 0, 53]; // el stub de systemd-resolved
    let no_resolvedor = [192u8, 0, 2, 60]; // TEST-NET, no es resolvedor
    let doh = [1u8, 1, 1, 1]; // Cloudflare, una IP DoH conocida
    {
        let mapa = ebpf
            .map_mut("SYSTEM_RESOLVERS")
            .expect("falta el mapa SYSTEM_RESOLVERS");
        let mut resolvers: BpfHashMap<_, Ip16, u8> =
            BpfHashMap::try_from(mapa).expect("SYSTEM_RESOLVERS no es un HashMap");
        resolvers
            .insert(Ip16(ip16(resolvedor)), 1, 0)
            .expect("no se pudo poblar el resolvedor");
    }
    {
        let mapa = ebpf.map_mut("KNOWN_DOH").expect("falta el mapa KNOWN_DOH");
        let mut doh_map: BpfHashMap<_, Ip16, u8> =
            BpfHashMap::try_from(mapa).expect("KNOWN_DOH no es un HashMap");
        doh_map
            .insert(Ip16(ip16(doh)), 1, 0)
            .expect("no se pudo poblar la IP DoH");
    }

    // Un pid NO forzado: su 53 a cualquier lado pasa, incluso a un no-resolvedor.
    assert_ne!(
        errno_de_connect_puerto(no_resolvedor, 53),
        libc::EPERM,
        "un pid sin FORCE_RESOLVER no tiene forzado el resolvedor: su 53 pasa"
    );

    // Marcar este pid como forzado (los dos bits), como hace el daemon al enrolar
    // un binario con regla de dominio con los resolvedores ya determinados.
    {
        let mapa = ebpf
            .map_mut("FORCE_RESOLVER")
            .expect("falta el mapa FORCE_RESOLVER");
        let mut forzar: BpfHashMap<_, u64, u8> =
            BpfHashMap::try_from(mapa).expect("FORCE_RESOLVER no es un HashMap");
        forzar
            .insert(key, FORCE_DNS | FORCE_DOH, 0)
            .expect("no se pudo marcar FORCE_RESOLVER");
    }

    // 53 a un no-resolvedor: cortado (se fuerza la resolución por el resolvedor).
    assert_eq!(
        errno_de_connect_puerto(no_resolvedor, 53),
        libc::EPERM,
        "un pid forzado no puede hablar DNS en claro con un no-resolvedor"
    );
    // 53 al resolvedor del sistema: pasa (si no, se rompería todo el DNS).
    assert_ne!(
        errno_de_connect_puerto(resolvedor, 53),
        libc::EPERM,
        "un pid forzado SÍ puede hablar DNS con el resolvedor del sistema"
    );
    // 853 (DoT) a un no-resolvedor: cortado, igual que el 53 en claro.
    assert_eq!(
        errno_de_connect_puerto(no_resolvedor, 853),
        libc::EPERM,
        "un pid forzado no puede hablar DoT con un no-resolvedor"
    );
    // 443 a una IP DoH conocida: cortado.
    assert_eq!(
        errno_de_connect_puerto(doh, 443),
        libc::EPERM,
        "un pid forzado no puede conectar al 443 de una IP DoH conocida"
    );
    // 443 a una IP que NO es DoH conocida: pasa (sólo se bloquea la lista DoH; un
    // DoH propio a una IP desconocida es el residual documentado).
    assert_ne!(
        errno_de_connect_puerto(no_resolvedor, 443),
        libc::EPERM,
        "el 443 a una IP que no es DoH conocida no se corta"
    );

    // Al desmarcar el pid, su 53 a un no-resolvedor vuelve a pasar.
    {
        let mapa = ebpf
            .map_mut("FORCE_RESOLVER")
            .expect("falta el mapa FORCE_RESOLVER");
        let mut forzar: BpfHashMap<_, u64, u8> =
            BpfHashMap::try_from(mapa).expect("FORCE_RESOLVER no es un HashMap");
        forzar
            .remove(&key)
            .expect("no se pudo desmarcar FORCE_RESOLVER");
    }
    assert_ne!(
        errno_de_connect_puerto(no_resolvedor, 53),
        libc::EPERM,
        "tras quitar FORCE_RESOLVER, el 53 vuelve a pasar"
    );
}
