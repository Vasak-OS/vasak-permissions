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
/// El tamaño del `ConnectionEvent` del programa (32 bytes con relleno explícito);
/// el parser del daemon usa los mismos desplazamientos.
const EVENTO_LEN: usize = 32;

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
    // SAFETY: llamadas a la API de sockets de POSIX con argumentos válidos; el
    // descriptor se cierra antes de salir.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return *libc::__errno_location();
        }
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = 80u16.to_be();
        addr.sin_addr.s_addr = u32::from_be_bytes([192, 0, 2, 1]).to_be();
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
}
