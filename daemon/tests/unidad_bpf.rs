//! La unidad del daemon deja pasar `bpf()` sin aflojar el resto.
//!
//! El cortafuegos por aplicación (issue #93) carga un programa eBPF, y para eso
//! llama `bpf()`. El filtro `@system-service` **no** incluye esa syscall, así que
//! sin `SystemCallFilter=bpf` la carga falla con EPERM en silencio: el daemon
//! arranca, el cortafuegos no, y nada lo delata salvo una línea en el diario.
//!
//! Esta prueba es roja sin el fix (la línea no estaba) y cuida que al abrirle la
//! puerta a `bpf()` no se haya aflojado el endurecimiento que el diseño dice que
//! se conserva.

const UNIDAD: &str = include_str!("../../packaging/vasak-permissions.service");

/// Las directivas activas (sin comentarios ni líneas vacías).
fn directivas() -> Vec<&'static str> {
    UNIDAD
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// `bpf()` tiene que estar permitido, y `@system-service` tiene que seguir: las
/// dos líneas se unen en el conjunto de permitidos, así que falta cualquiera de
/// las dos rompe algo distinto —sin `bpf` no carga el programa; sin
/// `@system-service` el daemon pierde el resto de las syscalls que necesita—.
#[test]
fn la_unidad_permite_bpf_sobre_system_service() {
    let d = directivas();
    assert!(
        d.contains(&"SystemCallFilter=@system-service"),
        "la unidad perdió «SystemCallFilter=@system-service»: el daemon se queda sin \
         las syscalls básicas de un servicio"
    );
    assert!(
        d.contains(&"SystemCallFilter=bpf"),
        "a la unidad le falta «SystemCallFilter=bpf»: la carga del programa eBPF del \
         cortafuegos falla con EPERM y el kill-switch de red no se activa"
    );
}

/// El endurecimiento que el diseño dice que se queda (sección 4): la carga BPF
/// no lo necesita relajado, así que sacar cualquiera de estas sería perder
/// contención sin ninguna razón del cortafuegos.
#[test]
fn la_unidad_conserva_el_endurecimiento_que_el_bpf_no_toca() {
    let d = directivas();
    for esperada in [
        "MemoryDenyWriteExecute=yes",
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectKernelModules=yes",
        "SystemCallErrorNumber=EPERM",
    ] {
        assert!(
            d.contains(&esperada),
            "la unidad perdió «{esperada}»: es parte del aislamiento que se mantiene \
             aunque se le abra la puerta a bpf()"
        );
    }
}
