//! El programa BPF del kill-switch de red por aplicación (M0 del issue #93) y su
//! mapa de conexiones en vivo (M1).
//!
//! Corre en el contexto del proceso que hace `connect()`, enganchado al cgroup
//! unificado (lo adjunta el daemon). Ahí lee el pid y el uid **del propio
//! syscall** —sin carrera y sin que la aplicación pueda mentir— y consulta el
//! mapa `BLOCKED`, que el daemon mantiene desde la política del usuario.
//!
//! Es de **sólo veredicto**: no resuelve el ejecutable (BPF no lee `/proc`; eso
//! lo hace el daemon en userspace), no escribe nada salvo el evento de
//! observación, no toca memoria del usuario salvo el contexto. Si el pid está
//! marcado `DENY`, corta el connect; si no, lo deja pasar (M0 es default-allow +
//! kill-switch opt-in).
//!
//! # El mapa en vivo (M1)
//!
//! Además del veredicto, cada `connect()` observado —permitido **y** bloqueado—
//! emite un evento al ring buffer `EVENTS` con el uid, el pid, el destino, el
//! puerto, el protocolo y el veredicto. El daemon lo lee, lo enriquece con el
//! ejecutable y lo sirve por `ListConnections`. La emisión va **después** de
//! computar el veredicto y no lo toca: el enforcement de M0 queda idéntico, esto
//! sólo observa. Si el ring está lleno, el evento se descarta —el mapa en vivo es
//! observacional, nunca demora ni cambia el `connect()`—.
//!
//! Dos programas idénticos, `connect4` y `connect6`, porque cubrir sólo IPv4
//! dejaría la evasión trivial por IPv6 (decisión 4 del diseño). La familia entra
//! como constante por programa, así que el verificador ve sólo el acceso al campo
//! del contexto que corresponde a cada punto de enganche (`user_ip4` en v4,
//! `user_ip6` en v6): la rama de la otra familia es código muerto que se elimina.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{cgroup_sock_addr, map},
    maps::{HashMap, RingBuf},
    programs::SockAddrContext,
};

/// `(uid << 32 | pid) → policy`. La clave lleva el uid porque el programa se
/// engancha en la raíz unificada y ve a todos los usuarios: sin él, dos sesiones
/// confundirían sus pids (sección 3 del diseño). El daemon escribe este mapa;
/// acá sólo se lee.
#[map]
static BLOCKED: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

/// El ring buffer por donde se emite cada conexión observada (M1). 256 KiB:
/// potencia de dos, múltiplo del tamaño de página, holgado para la ráfaga de
/// `connect()` de un arranque de sesión. El daemon lo lee y lo vacía; si se
/// llena, [`emit`] descarta el evento sin tocar el veredicto.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// El único valor que M0 escribe. Deja lugar a `allow` explícito y a un id de
/// set de IPs para M2 sin cambiar la forma del mapa.
const DENY: u8 = 1;

/// Para un programa `cgroup/connect`, 1 deja seguir el `connect()` y 0 lo corta
/// con EPERM. El veredicto, no un código de error.
const ALLOW: i32 = 1;
const BLOCK: i32 = 0;

/// Las dos familias que el evento distingue. `AF_INET`/`AF_INET6` de Linux; se
/// guardan como byte en el evento y el daemon elige v4 o v6 con esto.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// El evento que viaja por `EVENTS`. `#[repr(C)]` y compartido **byte a byte**
/// con el daemon (`firewall::conexiones`, que lo parsea por desplazamientos): una
/// prueba de correspondencia ata los dos lados, igual que con la clave del mapa.
/// 32 bytes, alineación 4; el relleno es explícito para que el objeto sea
/// reproducible y el parser del daemon no adivine el padding.
#[repr(C)]
struct ConnectionEvent {
    /// uid real del syscall.
    uid: u32,
    /// tgid (el «pid» que ve userspace).
    tgid: u32,
    /// Destino: IPv4 en los primeros 4 bytes, o los 16 de IPv6. En orden de red.
    dst: [u8; 16],
    /// Puerto de destino, en orden de host.
    port: u16,
    /// `AF_INET` o `AF_INET6`: qué parte de `dst` vale.
    family: u8,
    /// Protocolo del socket (`IPPROTO_TCP`, `IPPROTO_UDP`, …).
    proto: u8,
    /// `DENY` si el cortafuegos lo cortó, 0 si lo dejó pasar.
    verdict: u8,
    _pad: [u8; 3],
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    handle(&ctx, AF_INET)
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    handle(&ctx, AF_INET6)
}

/// El veredicto compartido por v4 y v6: mismo mapa, misma clave, misma regla, más
/// la emisión del evento de observación. `family` es constante en cada punto de
/// enganche, así que la rama de la otra familia en [`emit`] se elimina.
#[inline(always)]
fn handle(ctx: &SockAddrContext, family: u8) -> i32 {
    // `bpf_get_current_pid_tgid()` devuelve `tgid << 32 | pid`; el tgid es el
    // «pid» que ve userspace, el que el daemon resuelve a un ejecutable.
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() & 0xffff_ffff) as u32;
    let key = ((uid as u64) << 32) | (tgid as u64);

    // SAFETY: `HashMap::get` del lado BPF es unsafe por contrato; la clave es un
    // `u64` por valor y el acceso no sale del mapa.
    let bloqueado = matches!(unsafe { BLOCKED.get(&key) }, Some(&policy) if policy == DENY);

    // Después del veredicto y sin tocarlo: la emisión es observacional.
    emit(ctx, uid, tgid, family, bloqueado);

    if bloqueado {
        BLOCK
    } else {
        ALLOW
    }
}

/// Emite el evento de la conexión al ring buffer. Si está lleno, no hace nada: el
/// mapa en vivo nunca demora ni altera el `connect()`.
#[inline(always)]
fn emit(ctx: &SockAddrContext, uid: u32, tgid: u32, family: u8, bloqueado: bool) {
    let Some(mut slot) = EVENTS.reserve::<ConnectionEvent>(0) else {
        return;
    };

    let sa = ctx.sock_addr;
    // SAFETY: `sock_addr` es el contexto del hook, válido mientras corre el
    // programa; `user_ip4`/`user_ip6`/`user_port`/`protocol` son de lectura
    // directa permitida para `cgroup/connect`. `family` es constante por
    // programa, así que en `connect4` sólo se lee `user_ip4` y en `connect6` sólo
    // `user_ip6`: la otra rama es código muerto.
    let mut dst = [0u8; 16];
    let (port_raw, proto) = unsafe {
        if family == AF_INET6 {
            let ip6 = (*sa).user_ip6;
            let mut i = 0;
            while i < 4 {
                let b = ip6[i].to_ne_bytes();
                dst[i * 4] = b[0];
                dst[i * 4 + 1] = b[1];
                dst[i * 4 + 2] = b[2];
                dst[i * 4 + 3] = b[3];
                i += 1;
            }
        } else {
            // `user_ip4` es `__be32`; en el target little-endian sus bytes nativos
            // son los de la red, que es justo el orden del cuádruple punteado.
            let b = (*sa).user_ip4.to_ne_bytes();
            dst[0] = b[0];
            dst[1] = b[1];
            dst[2] = b[2];
            dst[3] = b[3];
        }
        ((*sa).user_port, (*sa).protocol as u8)
    };
    // `user_port` trae el puerto en orden de red en sus 16 bits bajos; a host.
    let port = u16::from_be((port_raw & 0xffff) as u16);

    // SAFETY: `reserve` entregó memoria alineada para un `ConnectionEvent`; se
    // escriben **todos** los campos antes de `submit`, así que nada queda sin
    // inicializar.
    let ev = slot.as_mut_ptr();
    unsafe {
        (*ev).uid = uid;
        (*ev).tgid = tgid;
        (*ev).dst = dst;
        (*ev).port = port;
        (*ev).family = family;
        (*ev).proto = proto;
        (*ev).verdict = if bloqueado { DENY } else { 0 };
        (*ev)._pad = [0u8; 3];
    }
    slot.submit(0);
}

/// Nunca se alcanza: el programa no hace nada que pueda entrar en pánico (ni
/// indexado, ni `unwrap`). Existe porque un crate `no_std` lo exige.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
