//! `store.email.interactions`: el historial de correo con una persona.
//!
//! Es un recurso **angosto** que la libreta de direcciones pide para la ficha de
//! un contacto. Estas pruebas cuidan las tres cosas que lo separan de
//! `store.email` y de `account.email`: que se reconozca exactamente con ese
//! texto, que sólo `vasak-contacts` lo pueda pedir, y que no se cuele entre las
//! áreas del almacén.
//!
//! Van por la API pública y sin nombrar la variante, para que fallen por una
//! afirmación y no por un error de compilación cuando falta el recurso.

use vasak_permissions_protocol::{may_request, Resource, StoreResource, SCOPED_BINARIES};

const ID: &str = "store.email.interactions";
const LIBRETA: &str = "/usr/bin/vasak-contacts";
const CALENDARIO: &str = "/usr/bin/vasak-calendar";

fn recurso() -> Resource {
    Resource::from_id(ID).unwrap_or_else(|| panic!("{ID} no se reconoce como recurso"))
}

fn area() -> StoreResource {
    match recurso() {
        Resource::Store(area) => area,
        otro => panic!("{ID} tenía que ser del almacén y es {otro:?}"),
    }
}

/// El texto queda escrito en disco: tiene que ir y volver igual.
#[test]
fn el_historial_de_correo_va_y_vuelve_con_el_mismo_texto() {
    assert_eq!(recurso().as_id(), ID);
    assert_eq!(area().as_id(), "email.interactions");
    assert_eq!(StoreResource::from_id("email.interactions"), Some(area()));
}

/// No es `store.email` leído de otra forma: son dos decisiones distintas.
#[test]
fn el_historial_de_correo_no_es_el_correo_guardado() {
    assert_ne!(recurso(), Resource::Store(StoreResource::Email));
    assert_ne!(recurso().as_id(), "store.email");
    assert_ne!(Resource::from_id("store.email"), Some(recurso()));
}

/// Falla cerrado: un id parecido no se adivina ni se recorta a `store.email`.
#[test]
fn un_id_parecido_al_del_historial_se_rechaza() {
    for id in [
        "store.email.interaction",
        "store.email.interactions.",
        "store.email.interactions.extra",
        "store.email.Interactions",
        "store.Email.interactions",
        "store.interactions",
        "store.email.interactions ",
        " store.email.interactions",
        "store.email.interactions\n",
        "store.email/interactions",
        "account.email.interactions",
        "account.interactions",
        "email.interactions",
    ] {
        assert_eq!(
            Resource::from_id(id),
            None,
            "'{id}' no tenía que reconocerse"
        );
    }
    assert_eq!(StoreResource::from_id("interactions"), None);
}

/// El texto con puntos de serde y el de `as_id` tienen que decir lo mismo: si
/// se separan, lo que viaja y lo que se guarda dejan de coincidir.
#[test]
fn serde_y_as_id_deletrean_igual_el_historial_de_correo() {
    let json = serde_json::to_string(&area()).unwrap();
    assert_eq!(json, "\"email.interactions\"");
    assert_eq!(
        serde_json::from_str::<StoreResource>(&json).unwrap(),
        area()
    );

    for otra in StoreResource::ALL {
        assert_eq!(
            serde_json::to_string(&otra).unwrap(),
            format!("\"{}\"", otra.as_id())
        );
    }
}

/// Sólo la libreta de direcciones lo puede pedir, y nada más del almacén ni de
/// las cuentas del correo.
#[test]
fn la_libreta_pide_el_historial_y_no_el_correo_ni_su_credencial() {
    assert!(
        may_request(LIBRETA, ID),
        "la libreta tenía que poder pedir {ID}"
    );
    assert!(may_request(LIBRETA, "account.contacts"));

    for prohibido in [
        "store.email",
        "store.calendar",
        "store.contacts",
        "account.email",
        "account.calendar",
        "account.chat",
        "account.drive",
        "account.tasks",
        "credentials",
        "camera",
        "microphone",
    ] {
        assert!(
            !may_request(LIBRETA, prohibido),
            "la libreta no tenía que poder pedir '{prohibido}'"
        );
    }
}

/// El alcance de la libreta no crece solo: son exactamente estos dos.
#[test]
fn el_alcance_de_la_libreta_son_sus_dos_recursos() {
    let (_, alcance) = SCOPED_BINARIES
        .iter()
        .find(|(binario, _)| *binario == LIBRETA)
        .expect("la libreta tiene alcance declarado");
    assert_eq!(*alcance, ["account.contacts", ID]);
}

/// Ninguna otra aplicación gana el historial de correo.
#[test]
fn ninguna_otra_aplicacion_puede_pedir_el_historial_de_correo() {
    let con_historial: Vec<&str> = SCOPED_BINARIES
        .iter()
        .filter(|(_, alcance)| alcance.contains(&ID))
        .map(|(binario, _)| *binario)
        .collect();
    assert_eq!(con_historial, [LIBRETA]);

    for otra in [
        "/usr/bin/vasak-mail",
        "/usr/bin/vasak-calendar",
        "/usr/bin/vasak-file-manager",
        "/usr/bin/vasak-accounts-sync",
    ] {
        assert!(
            !may_request(otra, ID),
            "{otra} no tenía que poder pedir {ID}"
        );
    }
}

/// Es un sub-permiso, no un área: `ALL` es lo que recorren los catálogos de
/// idioma y la pantalla de Configuración pensando en áreas sincronizables.
#[test]
fn el_historial_de_correo_no_es_un_area_del_almacen() {
    assert!(!StoreResource::ALL.contains(&area()));
    let ids: Vec<String> = StoreResource::ALL
        .iter()
        .map(|a| Resource::Store(a.clone()).as_id())
        .collect();
    assert_eq!(ids, ["store.email", "store.calendar", "store.contacts"]);
}

/// Decidirlo cambia algo (el sincronizador consulta antes de servir), pero un
/// rechazo no es una frontera, y por el portal no llega nunca.
#[test]
fn el_historial_de_correo_se_decide_pero_no_es_una_frontera() {
    let recurso = recurso();
    assert!(recurso.decision_has_effect());
    assert!(recurso.decision_has_effect_for(LIBRETA));
    assert!(!recurso.is_enforceable());

    let portal = vasak_permissions_protocol::portal_key("com.google.Chrome").unwrap();
    assert!(!recurso.decision_has_effect_for(&portal));
}

/// Los únicos `store.*` que aparecen en el alcance de alguna aplicación son el
/// historial de la libreta y el área del calendario (que lee los eventos del
/// almacén). Cierra el hueco que deja la prueba de «ningún área»: ésa sólo mira
/// las tres áreas, y un `store.*` nuevo o repartido de más pasaría sin que nadie
/// lo vea. La separación calendario/contactos queda fijada de los dos lados.
#[test]
fn los_unicos_recursos_del_almacen_en_un_alcance_son_el_historial_y_el_calendario() {
    let del_almacen: Vec<(&str, &str)> = SCOPED_BINARIES
        .iter()
        .flat_map(|(binario, alcance)| alcance.iter().map(move |id| (*binario, *id)))
        .filter(|(_, id)| id.starts_with("store."))
        .collect();
    assert_eq!(del_almacen, [(CALENDARIO, "store.calendar"), (LIBRETA, ID)]);
}

/// El calendario no se lleva nada de la libreta, ni la libreta nada del
/// calendario: lo guardado de uno no se ve desde la otra.
#[test]
fn el_almacen_del_calendario_y_el_de_la_libreta_no_se_mezclan() {
    for prohibido in [
        "store.contacts",
        "store.email",
        ID,
        "account.contacts",
        "account.email",
    ] {
        assert!(
            !may_request(CALENDARIO, prohibido),
            "el calendario no tenía que poder pedir '{prohibido}'"
        );
    }
    assert!(may_request(CALENDARIO, "store.calendar"));
    assert!(!may_request(LIBRETA, "store.calendar"));
}

/// El correo sigue sin alcance: ni el almacén del calendario le toca.
#[test]
fn el_correo_sigue_sin_alcance() {
    assert_eq!(
        SCOPED_BINARIES
            .iter()
            .find(|(binario, _)| *binario == "/usr/bin/vasak-mail")
            .map(|(_, alcance)| *alcance),
        Some(&[][..])
    );
    assert!(!may_request("/usr/bin/vasak-mail", "store.calendar"));
}
