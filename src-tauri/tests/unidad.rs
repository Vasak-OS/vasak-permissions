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

/// El backend del portal habla por el bus de **sesión**, que es un socket de
/// dominio UNIX. Si alguien saca `AF_UNIX` de la lista, el agente no puede
/// tomar su nombre y el portal vuelve a quedarse esperándolo.
#[test]
fn la_unidad_deja_pasar_el_bus_de_sesion() {
    let linea = UNIDAD
        .lines()
        .find(|l| l.starts_with("RestrictAddressFamilies="))
        .expect("la unidad ya no restringe familias de direcciones");
    assert!(
        linea.contains("AF_UNIX"),
        "sin AF_UNIX no hay bus de sesión, y sin bus de sesión no hay backend de portal: {linea}"
    );
}
