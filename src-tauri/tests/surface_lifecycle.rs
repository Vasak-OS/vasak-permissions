//! Que el diálogo de permisos mate su proceso de WebKit al esconderse y lo
//! reponga al mostrarse.
//!
//! Es una guarda de fuente, no de comportamiento: matar y recargar el proceso es
//! glue de GTK/WebKit que no se puede montar sin un display real. Lo que sí se
//! puede sostener es el cableado: si `clear` deja de armar la muerte, o
//! `open_window` deja de reponer la página antes de mostrarla, compila igual y
//! sólo se nota como un WebKit que nunca libera su RAM, o como un diálogo en
//! blanco.

const DIALOG: &str = include_str!("../src/dialog.rs");

/// Cuerpo de la primera `fn <firma>`, hasta su llave de cierre a la columna cero.
fn body_of(signature: &str) -> &'static str {
    let start = DIALOG
        .find(signature)
        .unwrap_or_else(|| panic!("no se encontró `{signature}`"));
    let rest = &DIALOG[start..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("no se encontró el fin de `{signature}`"));
    &rest[..end]
}

fn position(body: &str, needle: &str) -> usize {
    body.find(needle)
        .unwrap_or_else(|| panic!("falta `{needle}` en:\n{body}"))
}

#[test]
fn al_esconder_el_dialogo_se_arma_la_muerte_del_proceso() {
    let body = body_of("fn clear<");
    let hide = position(body, "window.hide()");
    let arm = position(body, "surface_lifecycle::arm_after_hide(app)");
    assert!(arm > hide, "arm_after_hide debe ir después de hide()");
}

#[test]
fn al_reusar_la_ventana_se_repone_el_proceso_antes_de_mostrarla() {
    let body = body_of("fn open_window<");
    let prepare = position(body, "surface_lifecycle::prepare_show(app)");
    let show = position(body, "window.show()");
    assert!(prepare < show, "prepare_show debe ir antes de show()");
}
