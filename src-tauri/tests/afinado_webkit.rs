//! El cableado del afinado del WebKit.
//!
//! Esto se mira sobre el texto de los fuentes y no sobre el programa corriendo
//! porque el afinado baja al `WebKitWebView` por el árbol de GTK y no se puede
//! ejercitar sin un display ni un WebKit reales. Lo que hay que sostener es que
//! las palancas sigan puestas, que el comando siga registrado en `lib.rs` y que
//! el frontend lo siga invocando al montar: si alguno de los tres se cae, el
//! afinado deja de aplicarse sin que nada falle al compilar.

const WEBKIT: &str = include_str!("../src/commands/webkit.rs");
const LIB: &str = include_str!("../src/lib.rs");
const APP_VUE: &str = include_str!("../../src/App.vue");

fn contiene(texto: &str, aguja: &str, donde: &str) {
    assert!(
        texto.contains(aguja),
        "no aparece «{aguja}» en {donde}. Si el afinado del WebKit se tocó, hay \
         que actualizar esta prueba; si se borró, leer el encabezado antes."
    );
}

#[test]
fn el_comando_expone_el_afinado() {
    contiene(WEBKIT, "pub fn tune_webview", "commands/webkit.rs");
}

#[test]
fn las_palancas_siguen_puestas() {
    contiene(
        WEBKIT,
        "set_enable_developer_extras(false)",
        "commands/webkit.rs",
    );
    contiene(
        WEBKIT,
        "set_enable_back_forward_navigation_gestures(false)",
        "commands/webkit.rs",
    );
    contiene(WEBKIT, "CacheModel::DocumentViewer", "commands/webkit.rs");
}

#[test]
fn el_comando_esta_registrado() {
    contiene(LIB, "commands::webkit::tune_webview", "lib.rs");
}

#[test]
fn el_frontend_lo_invoca_al_montar() {
    contiene(APP_VUE, "invoke('tune_webview')", "App.vue");
}
