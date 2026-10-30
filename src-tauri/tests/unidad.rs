//! La unidad y el código, atados.
//!
//! Son dos archivos en dos lenguajes distintos que tienen que nombrar el mismo
//! nombre de bus. Separarlos no rompe la compilación ni ninguna otra prueba: el
//! agente arrancaría igual y systemd lo esperaría para siempre, o lo daría por
//! arrancado sin que el backend exista, que es justamente el error que esta
//! unidad viene a evitar.

const UNIDAD: &str = include_str!("../../packaging/vasak-permissions-agent.service");
const PORTAL: &str = include_str!("../src/portal.rs");

/// El nombre tal como lo toma el código, leído del propio fuente.
fn nombre_del_backend() -> &'static str {
    PORTAL
        .split("BACKEND_NAME: &str = \"")
        .nth(1)
        .and_then(|resto| resto.split('"').next())
        .expect("no se encontró BACKEND_NAME en portal.rs")
}

#[test]
fn la_unidad_espera_exactamente_el_nombre_que_el_codigo_toma() {
    let esperado = format!("BusName={}", nombre_del_backend());
    assert!(
        UNIDAD.contains(&esperado),
        "la unidad no dice «{esperado}». Si los dos nombres se separan, systemd \
         espera un nombre que nadie va a tomar y la unidad nunca termina de arrancar"
    );
}

#[test]
fn la_unidad_se_da_por_arrancada_recien_cuando_el_nombre_existe() {
    assert!(
        UNIDAD.contains("\nType=dbus"),
        "la unidad volvió a darse por arrancada al hacer exec. Eso fue lo que \
         escondió durante meses que el nombre del backend tardaba quince segundos \
         en aparecer: `systemd-analyze --user blame` mostraba 82 ms"
    );
}

/// Las directivas activas de la unidad (las que no están comentadas).
fn directivas() -> Vec<&'static str> {
    UNIDAD
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

fn tiene(directiva: &str) -> bool {
    directivas().iter().any(|l| l.starts_with(directiva))
}

/// GTK3 carga los íconos de los botones de la ventana con gdk-pixbuf → glycin,
/// que aísla la decodificación en un `bwrap` anidado. Ese `bwrap` no arranca si
/// el proceso lleva un filtro seccomp, GTK trata el fallo como fatal y el agente
/// se cae al abrir el diálogo: sin diálogo no se concede ningún permiso. Cada
/// una de estas directivas instala un filtro seccomp (`ProtectHostname`,
/// `ProtectKernelTunables` y `ProtectControlGroups` no: son de espacios de
/// nombres de montaje/UTS y se conservan).
#[test]
fn la_unidad_no_instala_ningun_filtro_seccomp_que_tumbe_el_dialogo() {
    let instaladas: Vec<_> = [
        "SystemCallFilter=",
        "SystemCallArchitectures=",
        "SystemCallErrorNumber=",
        "LockPersonality=",
        "RestrictRealtime=",
        "RestrictSUIDSGID=",
        "RestrictAddressFamilies=",
        "ProtectClock=",
        "ProtectKernelLogs=",
        "ProtectKernelModules=",
    ]
    .into_iter()
    .filter(|d| tiene(d))
    .collect();
    assert!(
        instaladas.is_empty(),
        "la unidad volvió a instalar seccomp ({instaladas:?}): el diálogo de permisos \
         se cae al cargar sus íconos (glycin/bwrap no arranca bajo seccomp)"
    );
}

/// Lo que sí se conserva: el aislamiento que no usa seccomp. Si alguna se saca,
/// el agente que otorga permisos queda con menos contención de la acordada.
#[test]
fn la_unidad_conserva_el_aislamiento_que_no_usa_seccomp() {
    for esperada in [
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "PrivateTmp=yes",
        "ProtectSystem=full",
        "ProtectProc=invisible",
        "ProtectHostname=yes",
        "ProtectKernelTunables=yes",
        "ProtectControlGroups=yes",
        "PrivateDevices=yes",
        "BindPaths=-/dev/dri",
    ] {
        assert!(
            directivas().contains(&esperada),
            "a la unidad le falta «{esperada}»: es parte del aislamiento que se \
             mantiene aunque no pueda filtrar syscalls"
        );
    }
}
