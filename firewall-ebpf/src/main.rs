//! El programa BPF del kill-switch de red por aplicación (M0 del issue #93).
//!
//! Corre en el contexto del proceso que hace `connect()`, enganchado al cgroup
//! unificado (lo adjunta el daemon). Ahí lee el pid y el uid **del propio
//! syscall** —sin carrera y sin que la aplicación pueda mentir— y consulta el
//! mapa `BLOCKED`, que el daemon mantiene desde la política del usuario.
//!
//! Es de **sólo veredicto**: no resuelve el ejecutable (BPF no lee `/proc`; eso
//! lo hace el daemon en userspace), no escribe nada, no toca memoria del usuario
//! salvo el contexto. Si el pid está marcado `DENY`, corta el connect; si no,
//! lo deja pasar (M0 es default-allow + kill-switch opt-in).
//!
//! Dos programas idénticos, `connect4` y `connect6`, porque cubrir sólo IPv4
//! dejaría la evasión trivial por IPv6 (decisión 4 del diseño).

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

/// `(uid << 32 | pid) → policy`. La clave lleva el uid porque el programa se
/// engancha en la raíz unificada y ve a todos los usuarios: sin él, dos sesiones
/// confundirían sus pids (sección 3 del diseño). El daemon escribe este mapa;
/// acá sólo se lee.
#[map]
static BLOCKED: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

/// El único valor que M0 escribe. Deja lugar a `allow` explícito y a un id de
/// set de IPs para M2 sin cambiar la forma del mapa.
const DENY: u8 = 1;

/// Para un programa `cgroup/connect`, 1 deja seguir el `connect()` y 0 lo corta
/// con EPERM. El veredicto, no un código de error.
const ALLOW: i32 = 1;
const BLOCK: i32 = 0;

#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    verdict()
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(_ctx: SockAddrContext) -> i32 {
    verdict()
}

/// El veredicto compartido por v4 y v6: mismo mapa, misma clave, misma regla.
#[inline(always)]
fn verdict() -> i32 {
    // `bpf_get_current_pid_tgid()` devuelve `tgid << 32 | pid`; el tgid es el
    // «pid» que ve userspace, el que el daemon resuelve a un ejecutable.
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() & 0xffff_ffff) as u32;
    let key = ((uid as u64) << 32) | (tgid as u64);

    // SAFETY: `HashMap::get` del lado BPF es unsafe por contrato; la clave es un
    // `u64` por valor y el acceso no sale del mapa.
    match unsafe { BLOCKED.get(&key) } {
        Some(&policy) if policy == DENY => BLOCK,
        _ => ALLOW,
    }
}

/// Nunca se alcanza: el programa no hace nada que pueda entrar en pánico (ni
/// indexado, ni `unwrap`). Existe porque un crate `no_std` lo exige.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
