//! Afinado del WebKit de la ventana para bajar su consumo de memoria.
//!
//! Aparte del resto a propósito: baja al `WebKitWebView` por el árbol de GTK y no
//! se puede ejercitar sin un display ni un WebKit reales. Por eso vive en
//! `commands/`, que el análisis de cobertura excluye —igual que los `.vue`—. Lo
//! dispara el frontend al montar (`invoke('tune_webview')`): para entonces la
//! ventana y su webview ya existen, sin un `.setup` sin cubrir en `lib.rs`.

use gtk::prelude::*;

fn find_webkit_webview(container: &gtk::Container) -> Option<webkit2gtk::WebView> {
    for child in container.children() {
        if child.type_().name() == "WebKitWebView" {
            return child.downcast::<webkit2gtk::WebView>().ok();
        }
        if let Some(child_container) = child.downcast_ref::<gtk::Container>() {
            if let Some(found) = find_webkit_webview(child_container) {
                return Some(found);
            }
        }
    }
    None
}

/// Palancas **seguras** para una ventana común de aplicación: sin extras de
/// desarrollo, sin gestos de navegación atrás/adelante (no navega a ningún lado)
/// y con el caché de un visor de documento, no el de un navegador. No se toca la
/// aceleración por hardware ni WebGL: una ventana que anima su UI tironearía.
fn tune_webkit(webview: &webkit2gtk::WebView) {
    use webkit2gtk::{CacheModel, SettingsExt, WebContextExt, WebViewExt};

    if let Some(settings) = WebViewExt::settings(webview) {
        settings.set_enable_developer_extras(false);
        settings.set_enable_back_forward_navigation_gestures(false);
    }
    if let Some(context) = WebViewExt::web_context(webview) {
        context.set_cache_model(CacheModel::DocumentViewer);
    }
}

/// Afina el WebKit de la ventana que hace la llamada. Lo invoca el frontend al montar.
#[tauri::command]
pub fn tune_webview(window: tauri::WebviewWindow) {
    let Ok(gtk_window) = window.gtk_window() else {
        return;
    };
    let container = gtk_window.upcast::<gtk::Container>();
    let Some(webview) = find_webkit_webview(&container) else {
        eprintln!("[vasak-permissions-agent] no se encontró el WebKitWebView para afinar");
        return;
    };
    tune_webkit(&webview);
}
