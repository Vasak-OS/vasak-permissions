//! Matar el `WebKitWebProcess` de la ventana del diálogo cuando está escondida,
//! para liberar su RAM (~150 MB), y reponerlo recargando al volver a mostrarla.
//!
//! La ventana del diálogo se crea perezosa —no existe hasta el primer pedido— y
//! desde ahí es residente: entre pedidos se esconde, no se destruye (destruir un
//! webview re-parenteado deja colgado su proceso bajo wry/GTK). Entre pedidos,
//! que es casi toda la sesión, su proceso de WebKit seguía vivo sin hacer nada.
//! Acá se programa matarlo tras una gracia escondida; al mostrarla de nuevo se
//! recarga la página y WebKit vuelve a levantar el proceso.
//!
//! **No** se destruye la ventana: `terminate_web_process()` baja el proceso de
//! verdad sin tocar el widget, y `reload()` lo repone.
//!
//! Como al mostrar se recarga, el pedido en vuelo se repondría solo: la vista ya
//! lee qué mostrar con el comando `pending_request` al montar (y otra vez cuando
//! la ventana toma el foco, que es como el diálogo reusa la misma ventana entre
//! preguntas). Tras recargar, la página remonta y vuelve a preguntar; no hace
//! falta guardar ni reenviar nada acá. Además el diálogo es de a uno —un segundo
//! pedido mientras hay uno abierto se rechaza—, así que no hay pedido viejo que
//! pueda pisar al nuevo.
//!
//! Vive en `commands/`, excluido de cobertura como `webkit.rs`: baja al webview
//! por GTK y no se puede montar sin un display real. La única parte pura
//! —[`reload_needed`]— va con su prueba acá abajo.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tauri::{AppHandle, Manager};

use crate::dialog::WINDOW_LABEL;

/// Cuánto espera la ventana escondida antes de matar su proceso. Corto: la
/// ventana casi no se usa, así que se libera a los pocos segundos de cada cierre.
const GRACE: Duration = Duration::from_secs(5);

/// Si el proceso se mató y, por eso, hay que recargar antes de mostrar.
static TERMINATED: AtomicBool = AtomicBool::new(false);

/// Generación de la muerte pendiente. Rearmar o cancelar la incrementa; la tarea
/// dormida, y el cierre que corre en el hilo principal, no matan si la encuentran
/// distinta. Es un temporizador cancelable sin un `SourceId` de glib, que no
/// cruza hilos.
static GEN: AtomicU64 = AtomicU64::new(0);

/// Decide, pura, si mostrar necesita recargar: sólo cuando el proceso se mató.
///
/// Trivial, pero es la regla que sostiene todo lo demás y la única parte de este
/// módulo que se puede probar sin un display.
pub fn reload_needed(terminated: bool) -> bool {
    terminated
}

/// Programa matar el proceso tras [`GRACE`] escondida. Reemplaza cualquier muerte
/// pendiente. Seguro desde cualquier hilo.
///
/// Genérica en el runtime —como el agente del diálogo— para que las pruebas usen
/// el de mentira de Tauri; en producción siempre es Wry.
pub fn arm_after_hide<R: tauri::Runtime>(app: &AppHandle<R>) {
    let generation = GEN.fetch_add(1, Ordering::SeqCst) + 1;
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(GRACE).await;
        maybe_terminate(&app, generation);
    });
}

/// Cancela la muerte pendiente. Se llama al ir a mostrar: incrementar la
/// generación invalida tanto la tarea dormida como un cierre ya encolado en el
/// hilo principal.
pub fn cancel<R: tauri::Runtime>(_app: &AppHandle<R>) {
    GEN.fetch_add(1, Ordering::SeqCst);
}

/// Deja la ventana lista para mostrarse: cancela la muerte pendiente y, si el
/// proceso ya se había matado, recarga para reponerlo.
///
/// `cancel` sube la generación **antes** de encolar nada, así cualquier muerte
/// pendiente —dormida o ya en la cola del hilo principal— ve la generación nueva
/// y no mata. La decisión de recargar va **en el hilo principal**, serializada
/// con [`maybe_terminate`]: si quedara en este hilo, entre leer `TERMINATED` y
/// que una muerte en el hilo principal lo pusiera en `true` habría una ventana en
/// la que la página se mostraría con el proceso muerto y sin recargar. En el hilo
/// principal, o la muerte corrió antes (`TERMINATED` en `true` → recarga) o este
/// closure corrió antes (la generación ya subió y la muerte se saltea).
pub fn prepare_show<R: tauri::Runtime>(app: &AppHandle<R>) {
    cancel(app);
    let app_main = app.clone();
    let _ = app.run_on_main_thread(move || {
        if reload_needed(TERMINATED.swap(false, Ordering::SeqCst)) {
            reload_on_main(&app_main);
        }
    });
}

/// Mata el proceso si la muerte sigue vigente. Corre en el hilo principal de GTK
/// y vuelve a mirar la generación ahí: si un `cancel` (un show) la cambió
/// mientras dormía o mientras esperaba en la cola, no mata.
fn maybe_terminate<R: tauri::Runtime>(app: &AppHandle<R>, generation: u64) {
    let app_main = app.clone();
    let _ = app.run_on_main_thread(move || {
        if GEN.load(Ordering::SeqCst) != generation {
            return;
        }
        if let Some(window) = app_main.get_webview_window(WINDOW_LABEL) {
            // Un `show` que entró en el hueco entre `hide()` y `arm_after_hide`
            // (otro pedido justo al cerrarse el anterior) rearma la generación a
            // este mismo valor, así que la guarda de arriba no lo ataja: la
            // ventana está visible y en uso. No se mata; el próximo `hide` rearma.
            // Ante la duda (`is_visible` falla) no se mata: blanquear un diálogo
            // en uso dejaría a `ask` esperando para siempre, y perder una
            // reclamación de RAM es barato —el próximo `hide` la vuelve a programar.
            if window.is_visible().unwrap_or(true) {
                return;
            }
            let _ = window.with_webview(|platform| {
                use webkit2gtk::WebViewExt;
                platform.inner().terminate_web_process();
            });
            TERMINATED.store(true, Ordering::SeqCst);
        }
    });
}

/// Recarga la ventana, con lo que WebKit respawnea el proceso que
/// [`maybe_terminate`] mató. Ya corre en el hilo principal: lo llama el closure
/// de [`prepare_show`], que [`AppHandle::run_on_main_thread`] despacha ahí.
fn reload_on_main<R: tauri::Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window(WINDOW_LABEL) {
        let _ = window.with_webview(|platform| {
            use webkit2gtk::WebViewExt;
            platform.inner().reload();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solo_recarga_si_el_proceso_se_mato() {
        assert!(reload_needed(true));
        assert!(!reload_needed(false));
    }
}
