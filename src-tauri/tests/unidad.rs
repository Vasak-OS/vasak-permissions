//! La unidad y el código, atados.
//!
//! Son dos archivos en dos lenguajes distintos que tienen que nombrar el mismo
//! nombre de bus. Separarlos no rompe la compilación ni ninguna otra prueba: el
//! agente arrancaría igual y systemd lo esperaría para siempre, o lo daría por
//! arrancado sin que el backend exista, que es justamente el error que esta
//! unidad viene a evitar.

const UNIDAD: &str = include_str!("../../packaging/vasak-permissions-agent.service");
const PORTAL: &str = include_str!("../src/portal.rs");
const PERFIL: &str = include_str!("../../packaging/vasak-permissions-agent.apparmor");

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

/// Las reglas activas del perfil AppArmor (sin comentarios ni líneas vacías).
fn reglas_del_perfil() -> Vec<&'static str> {
    PERFIL
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Sin el perfil el agente no tiene contención de red: al sacar seccomp se perdió
/// `RestrictAddressFamilies`. Es «roja sin el fix» por construcción: el
/// `include_str!` de arriba no compila si el archivo no existe.
#[test]
fn el_perfil_se_engancha_al_binario_del_agente_y_le_deniega_la_red_ip() {
    let reglas = reglas_del_perfil();
    assert!(
        reglas
            .iter()
            .any(|l| l.starts_with("profile ") && l.contains("/usr/bin/vasak-permissions-agent")),
        "el perfil no se engancha a /usr/bin/vasak-permissions-agent: no confinaría al agente"
    );
    for denegada in ["deny network inet,", "deny network inet6,"] {
        assert!(
            reglas.contains(&denegada),
            "al perfil le falta «{denegada}»: el agente volvería a poder abrir sockets IP"
        );
    }
}

/// Lo que el `bwrap` de glycin y el D-Bus necesitan: si el perfil las quita, el
/// diálogo vuelve a caerse al decodificar íconos o el agente no habla con el servicio.
#[test]
fn el_perfil_conserva_lo_que_el_bwrap_de_glycin_y_el_dbus_necesitan() {
    let reglas = reglas_del_perfil();
    for necesaria in ["userns,", "mount,", "unix,", "dbus,"] {
        assert!(
            reglas.contains(&necesaria),
            "al perfil le falta «{necesaria}»: el diálogo se cae o el agente pierde el D-Bus"
        );
    }
}

/// Sin `attach_disconnected` AppArmor niega el socket del bus de D-Bus (su ruta
/// queda «desconectada» por el espacio de nombres de montaje de la unidad) y el
/// agente no se registra: sin diálogo no se concede ningún permiso.
#[test]
fn el_perfil_tolera_las_rutas_desconectadas_que_el_bus_necesita() {
    let linea = reglas_del_perfil()
        .into_iter()
        .find(|l| l.starts_with("profile "))
        .expect("el perfil no declara su `profile`");
    assert!(
        linea.contains("attach_disconnected"),
        "a «{linea}» le falta flags=(attach_disconnected): el agente no llega al bus de D-Bus"
    );
}

/// Sin esto un agente corrompido cambiaría a un perfil sin esta contención (o a
/// ninguno) y recuperaría la red IP que el perfil le quita.
#[test]
fn el_perfil_no_deja_saltar_a_otro_perfil() {
    assert!(
        reglas_del_perfil().contains(&"deny change_profile,"),
        "falta «deny change_profile,»: un agente corrompido saltaría a unconfined y recuperaría inet"
    );
}

/// El agente no tiene por qué tocar credenciales: el llavero es lo más sensible.
#[test]
fn el_perfil_niega_al_agente_el_llavero_y_las_credenciales() {
    let reglas = reglas_del_perfil();
    for negada in [
        "audit deny @{HOME}/.local/share/vasak-keyring/** rwkl,",
        "audit deny @{HOME}/.ssh/** rwkl,",
        "audit deny @{HOME}/.gnupg/** rwkl,",
    ] {
        assert!(
            reglas.contains(&negada),
            "al perfil le falta «{negada}»: el agente podría leer credenciales del usuario"
        );
    }
}

/// El perfil existe justamente para no usar seccomp (comentarios aparte, que lo
/// nombran para explicar por qué).
#[test]
fn el_perfil_no_reintroduce_seccomp() {
    let con_seccomp: Vec<_> = reglas_del_perfil()
        .into_iter()
        .filter(|l| l.to_lowercase().contains("seccomp"))
        .collect();
    assert!(
        con_seccomp.is_empty(),
        "el perfil volvió a tocar seccomp ({con_seccomp:?}): glycin/bwrap no arranca bajo seccomp"
    );
}
