//! La unidad del daemon deja pasar `bpf()` sin aflojar el resto.
//!
//! El cortafuegos por aplicación (issue #93) carga un programa eBPF, y para eso
//! llama `bpf()`, que el filtro `@system-service` **no** incluye. La
//! infraestructura está en M0 pero todavía **sin llamador en el binario** —el
//! cableado con la política es el PR siguiente—, así que el daemon no la carga al
//! arrancar por ahora. La directiva `SystemCallFilter=bpf` se pre-provisiona
//! igual: cuando ese cableado la encienda, sin ella la carga fallaría con EPERM
//! en silencio —el daemon arranca, el cortafuegos no, y nada lo delata salvo una
//! línea en el diario—, y se deja lista ahora para no tener que tocar el
//! endurecimiento en aquel PR.
//!
//! Esta prueba cuida que la directiva esté y que, al abrirle la puerta a
//! `bpf()`, no se haya aflojado el endurecimiento que el diseño dice que se
//! conserva.

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
        "a la unidad le falta «SystemCallFilter=bpf»: cuando el PR siguiente cablee el \
         cortafuegos, la carga del programa eBPF fallaría con EPERM y el corte de egreso \
         por connect() no se activaría"
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
