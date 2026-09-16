//! The dialog agent.
//!
//! Sits in the user's session with **no window at all** until the permission
//! service has something to ask. Creating a hidden window instead would keep a
//! WebKit process resident — about 150 MB — for a dialog that appears a handful
//! of times in the life of an installation.

mod aviso;
mod capturas;
mod dialog;
mod locales;
mod mas_tarde;
mod politica;
mod portal;
mod portal_screencast;
mod service;

use tauri::Manager;

/// Keeps the portal's session-bus connection alive in app state.
struct PortalConnection(#[allow(dead_code)] zbus::Connection);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // El backend del portal toma su nombre **antes** de construir Tauri.
    //
    // Construir Tauri inicializa GTK, y `GtkApplication` sondea el gestor de
    // sesión al registrarse: eso activa `xdg-desktop-portal` y se queda
    // esperando. El portal, a su vez, no termina de arrancar hasta encontrar el
    // backend de `org.freedesktop.impl.portal.Access`, que `vasak-portals.conf`
    // rutea a este proceso. Tomar el nombre después —dentro de `setup()`, que
    // Tauri corre adentro de `build()`— dejaba a los dos esperándose hasta que
    // systemd mataba al portal por plazo vencido, y esos quince segundos los
    // pagaba toda aplicación GTK que arrancara en ese rato, el escritorio
    // incluido.
    //
    // Este orden es el arreglo, así que no se puede cambiar sin volver a
    // romperlo; hay una prueba que lo sostiene.
    let (cuando, mas_tarde) = mas_tarde::hueco();
    let conexion_del_portal = match tauri::async_runtime::block_on(portal::serve(mas_tarde)) {
        Ok(conexion) => Some(conexion),
        Err(error) => {
            // Fallar acá cuesta el diálogo con cara de VasakOS y nada más, así
            // que no puede impedir que el agente sirva al servicio de permisos.
            eprintln!("[vasak-permissions-agent] sin backend de portal: {error}");
            None
        }
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_i18n_vsk::init_with_path(
            Some(locales::idioma_del_sistema()),
            locales::directorio(),
        ))
        .plugin(tauri_plugin_config_manager::init())
        .plugin(tauri_plugin_vicons::init())
        .invoke_handler(tauri::generate_handler![
            dialog::pending_request,
            dialog::answer,
        ])
        .setup(move |app| {
            app.manage(dialog::DialogState::default());

            // Recién acá se le muestra la aplicación al backend del portal, y
            // después del estado del diálogo a propósito: un pedido que hubiera
            // llegado durante el arranque se despierta en esta línea, y tiene
            // que encontrar dónde dibujar.
            cuando.llenar(app.handle().clone());

            if let Some(conexion) = conexion_del_portal {
                // Held for the life of the process: dropping it would give the
                // name back and the portal would fall through to another
                // backend mid-session.
                app.manage(PortalConnection(conexion));
            }

            let handle = app.handle().clone();
            // Registering has to happen after the app is up so a request that
            // arrives immediately finds somewhere to draw.
            tauri::async_runtime::spawn(async move {
                if let Err(error) = service::connect_and_register(handle).await {
                    eprintln!(
                        "[vasak-permissions-agent] no se pudo registrar contra el servicio: {error}"
                    );
                }
            });
            Ok(())
        })
        // Without this the process would exit as soon as the dialog window is
        // closed, and the next request would find no agent registered.
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|_app, event| {
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                api.prevent_exit();
            }
        });
}
