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
//!
//! # Forzar el resolvedor del sistema (M2, PR-C)
//!
//! Una regla por dominio sólo es efectiva si la app resuelve por el resolvedor
//! que el daemon observa (el snoop). Una app que corre su **propio** DoH/DoT
//! esconde el dominio y evade la regla. Para los pids de binarios con **alguna**
//! regla de dominio —los que el daemon marca en `FORCE_RESOLVER`— se cierra esa
//! evasión, ADITIVO al kill-switch y al bloqueo por dominio:
//!
//! - **DNS en claro (53) y DoT (853):** se corta el `connect()` si el destino
//!   **no** es un resolvedor del sistema (`SYSTEM_RESOLVERS`), forzando la
//!   resolución por el resolvedor observable.
//! - **DoH (443):** se corta el `connect()` si el destino está en la lista de IPs
//!   de proveedores DoH conocidos (`KNOWN_DOH`), una lista estática **mejor
//!   esfuerzo** que el daemon puebla y mantiene.
//!
//! El valor de `FORCE_RESOLVER` es un bitmask: `FORCE_DNS` activa el corte de
//! 53/853 y `FORCE_DOH` el de 443. El daemon deja `FORCE_DNS` **apagado** cuando
//! no pudo determinar los resolvedores del sistema (fail hacia no-romper: sin eso
//! bloquearía todo el DNS de la app); `FORCE_DOH` va siempre, porque su lista es
//! estática y segura. Un DoH propio a una IP **fuera** de la lista sigue evadiendo
//! la regla: es un residual conocido, no un cierre total.

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

/// El set de `(clave de pid, IP) → DENY` del bloqueo por dominio (M2). El daemon
/// lo puebla **sólo** para los pids de binarios con una regla de dominio, con las
/// IPs que el snoop de DNS vio resolver a esos dominios (ver `firewall::dominio`
/// en el daemon). El programa, además del kill-switch de M0, corta el `connect()`
/// de un pid a una IP si la pareja está acá.
///
/// # Por qué la clave lleva el pid y no sólo la IP
///
/// El bloqueo por dominio es **por aplicación**: "a esta app, este dominio". Como
/// la mayoría de las apps del escritorio corren bajo el mismo uid, cortar por
/// `(uid, IP)` bloquearía el dominio para **todas**. Al meter el pid en la clave,
/// sólo los pids del binario con la regla —que el daemon enrola reusando el
/// enrolado por pid de M0— tienen entradas, así que el corte es por binario. El
/// daemon pone una entrada por cada pid vivo del binario y cada IP resuelta.
///
/// Sin reglas de dominio este mapa está **vacío** y cada consulta falla, así que
/// el veredicto queda idéntico al de M0 (aditivo).
#[map]
static DOMAIN_BLOCKED: HashMap<DomainKey, u8> = HashMap::with_max_entries(4096, 0);

/// La clave de [`DOMAIN_BLOCKED`]: la misma clave de pid de `BLOCKED`
/// (`uid << 32 | tgid`) más la IP de destino, en el mismo formato de 16 bytes que
/// `ConnectionEvent.dst` (IPv4 en los primeros 4 bytes, los 16 de IPv6). `repr(C)`
/// y compartida **byte a byte** con el daemon (`firewall::clave_dominio`), que la
/// arma con el mismo layout; una prueba de correspondencia ata los dos lados.
#[repr(C)]
struct DomainKey {
    /// `uid << 32 | tgid`, idéntica a la clave de `BLOCKED`.
    pid_key: u64,
    /// IP de destino: IPv4 en los primeros 4 bytes, o los 16 de IPv6. Orden de red.
    ip: [u8; 16],
}

/// El marcador «este pid está bajo una regla de dominio» (M2, PR-C). El daemon lo
/// puebla con los pids de binarios con **alguna** regla de dominio, reusando el
/// enrolado por pid de PR-B; la clave es la misma de `BLOCKED` (`uid << 32 | pid`)
/// y el valor es un bitmask ([`FORCE_DNS`] | [`FORCE_DOH`]). Sin pids enrolados
/// este mapa está **vacío** y el veredicto queda idéntico (aditivo).
#[map]
static FORCE_RESOLVER: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

/// Las IPs de los resolvedores del sistema (stub de systemd-resolved +
/// nameservers de `/etc/resolv.conf`), que el daemon puebla y mantiene. Un pid
/// forzado con [`FORCE_DNS`] sólo puede hablar DNS/DoT con una IP de acá. Mismo
/// formato de 16 bytes que `ConnectionEvent.dst` (IPv4 en los primeros 4).
#[map]
static SYSTEM_RESOLVERS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);

/// Las IPs de proveedores DoH conocidos (lista estática **mejor esfuerzo** que el
/// daemon embebe y puebla). Un pid forzado con [`FORCE_DOH`] no puede conectar al
/// 443 de ninguna de estas IPs. Mismo formato de 16 bytes.
#[map]
static KNOWN_DOH: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

/// El único valor que M0 escribe. Deja lugar a `allow` explícito y a un id de
/// set de IPs para M2 sin cambiar la forma del mapa.
const DENY: u8 = 1;

/// Bits del valor de [`FORCE_RESOLVER`]. `FORCE_DNS` fuerza la resolución por el
/// resolvedor del sistema (corta 53/853 a IPs que no son resolvedor); `FORCE_DOH`
/// corta el 443 a las IPs DoH conocidas. **Tienen que coincidir** con los del
/// daemon (`firewall::FORCE_DNS`/`FORCE_DOH`); una prueba de correspondencia los
/// ata.
const FORCE_DNS: u8 = 1;
const FORCE_DOH: u8 = 2;

/// Los puertos que el forzado del resolvedor mira: DNS en claro, DoT y DoH.
const PORT_DNS: u16 = 53;
const PORT_DOT: u16 = 853;
const PORT_DOH: u16 = 443;

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

/// El veredicto compartido por v4 y v6: el kill-switch de M0, el bloqueo por
/// dominio de M2 aditivo encima, y la emisión del evento de observación. `family`
/// es constante en cada punto de enganche, así que la rama de la otra familia en
/// [`destino`] se elimina.
#[inline(always)]
fn handle(ctx: &SockAddrContext, family: u8) -> i32 {
    // `bpf_get_current_pid_tgid()` devuelve `tgid << 32 | pid`; el tgid es el
    // «pid» que ve userspace, el que el daemon resuelve a un ejecutable.
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() & 0xffff_ffff) as u32;
    let key = ((uid as u64) << 32) | (tgid as u64);

    // El destino se lee una sola vez acá: lo usan el match por dominio y la
    // emisión del evento.
    let (dst, port, proto) = destino(ctx, family);

    // M0 — kill-switch de red por app. Si el pid está en DENY, se corta.
    // SAFETY: `HashMap::get` del lado BPF es unsafe por contrato; la clave es un
    // `u64` por valor y el acceso no sale del mapa.
    let kill_switch = matches!(unsafe { BLOCKED.get(&key) }, Some(&policy) if policy == DENY);

    // M2 — bloqueo por dominio, ADITIVO a M0. Sólo pega si el daemon metió esta
    // (clave de pid, IP) en `DOMAIN_BLOCKED` —cosa que hace únicamente para los
    // pids de binarios con una regla de dominio—. Con el mapa vacío (sin reglas)
    // este `get` falla siempre y el veredicto es el mismo que el de M0.
    // SAFETY: igual que arriba; la clave es un `repr(C)` por valor y el acceso no
    // sale del mapa.
    let domain_key = DomainKey {
        pid_key: key,
        ip: dst,
    };
    let dominio_bloqueado =
        matches!(unsafe { DOMAIN_BLOCKED.get(&domain_key) }, Some(&policy) if policy == DENY);

    // M2 PR-C — forzar el resolvedor del sistema, ADITIVO. Sólo se mira el mapa
    // para los tres puertos que importan (53/853/443) y sólo pega si el pid está
    // en `FORCE_RESOLVER` (binario con regla de dominio). Para cualquier otro pid
    // o puerto el `get` ni se consulta y el veredicto es el mismo de arriba.
    let resolver_forzado = if matches!(port, PORT_DNS | PORT_DOT | PORT_DOH) {
        // SAFETY: igual que arriba; la clave es un `u64` por valor y el acceso no
        // sale del mapa.
        match unsafe { FORCE_RESOLVER.get(&key) } {
            Some(&flags) => fuerza_resolvedor(flags, dst, port),
            None => false,
        }
    } else {
        false
    };

    let bloqueado = kill_switch || dominio_bloqueado || resolver_forzado;

    // Después del veredicto y sin tocarlo: la emisión es observacional.
    emit(uid, tgid, family, dst, port, proto, bloqueado);

    if bloqueado {
        BLOCK
    } else {
        ALLOW
    }
}

/// El corte del forzado del resolvedor para un pid enrolado, por puerto (M2 PR-C).
/// Es la **misma decisión** que `firewall::resolver::corta_por_resolvedor` del
/// daemon —probada ahí sin root—, con los dos booleanos resueltos acá contra los
/// mapas: `SYSTEM_RESOLVERS` (¿el destino es un resolvedor del sistema?) y
/// `KNOWN_DOH` (¿es una IP DoH conocida?).
///
/// - 53/853 (DNS en claro y DoT): corta si `FORCE_DNS` está y el destino **no** es
///   resolvedor del sistema.
/// - 443 (DoH): corta si `FORCE_DOH` está y el destino **sí** es DoH conocido.
#[inline(always)]
fn fuerza_resolvedor(flags: u8, dst: [u8; 16], port: u16) -> bool {
    match port {
        PORT_DNS | PORT_DOT => {
            // SAFETY: la clave es un `[u8; 16]` por valor y el acceso no sale del
            // mapa; sólo se mira si está presente.
            flags & FORCE_DNS != 0 && unsafe { SYSTEM_RESOLVERS.get(&dst) }.is_none()
        }
        PORT_DOH => flags & FORCE_DOH != 0 && unsafe { KNOWN_DOH.get(&dst) }.is_some(),
        _ => false,
    }
}

/// Lee el destino del `connect()` del contexto: la IP en 16 bytes (IPv4 en los
/// primeros 4, los 16 de IPv6), el puerto en orden de host y el protocolo. Se lee
/// una vez y lo comparten el match por dominio y [`emit`].
#[inline(always)]
fn destino(ctx: &SockAddrContext, family: u8) -> ([u8; 16], u16, u8) {
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
    (dst, port, proto)
}

/// Emite el evento de la conexión al ring buffer. Si está lleno, no hace nada: el
/// mapa en vivo nunca demora ni altera el `connect()`. No devuelve nada y no toca
/// el veredicto: sólo observa.
#[inline(always)]
fn emit(uid: u32, tgid: u32, family: u8, dst: [u8; 16], port: u16, proto: u8, bloqueado: bool) {
    let Some(mut slot) = EVENTS.reserve::<ConnectionEvent>(0) else {
        return;
    };

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
