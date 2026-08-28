//! The dialog agent.
//!
//! Sits in the user's session with **no window at all** until the permission
//! service has something to ask. Creating a hidden window instead would keep a
//! WebKit process resident — about 150 MB — for a dialog that appears a handful
//! of times in the life of an installation.

mod dialog;
mod locales;
mod portal;
mod service;

use tauri::Manager;

/// Keeps the portal's session-bus connection alive in app state.
struct PortalConnection(#[allow(dead_code)] zbus::Connection);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
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
        .setup(|app| {
            app.manage(dialog::DialogState::default());

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

            // The desktop portal's dialogs, on the session bus. Failing here
            // costs the portal its VasakOS-looking prompt and nothing else, so
            // it must not stop the agent from serving the permission service.
            let portal_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                match portal::serve(portal_handle.clone()).await {
                    Ok(connection) => {
                        // Held for the life of the process: dropping it would
                        // give the name back and the portal would fall through
                        // to another backend mid-session.
                        portal_handle.manage(PortalConnection(connection));
                    }
                    Err(error) => eprintln!(
                        "[vasak-permissions-agent] sin backend de portal: {error}"
                    ),
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
