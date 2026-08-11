//! The desktop portal's permission dialog.
//!
//! `xdg-desktop-portal` handles a program's request for the camera, the
//! location, running in the background and so on, and asks a *backend* to put
//! the question to the person. Implementing that backend is what makes those
//! dialogs look like the rest of VasakOS instead of borrowing GNOME's.
//!
//! What this is **not** is enforcement by the VasakOS permission service. The
//! portal remembers these answers in its own store, and it tells the backend
//! only an `app_id`, which is empty for anything outside a sandbox — so there
//! is nothing to record a per-program decision against. The two are kept
//! separate deliberately, and the dialog says which one it is looking at.

use tauri::AppHandle;
use zbus::interface;
use zbus::zvariant::{ObjectPath, OwnedValue};

use crate::dialog::{PortalQuestion, Question};

/// The name a portal backend is found under. It has to match the `.portal`
/// file installed alongside, or the portal never looks here.
pub const BACKEND_NAME: &str = "org.freedesktop.impl.portal.desktop.vasak";
pub const BACKEND_PATH: &str = "/org/freedesktop/portal/desktop";

/// Response codes from the portal specification.
const RESPONSE_GRANTED: u32 = 0;
const RESPONSE_CANCELLED: u32 = 1;

pub struct AccessBackend {
    pub app: AppHandle,
}

#[interface(name = "org.freedesktop.impl.portal.Access")]
impl AccessBackend {
    /// Puts the portal's question to the person.
    ///
    /// The reply is `(response, results)`. Nothing is returned in `results`:
    /// that carries the answers to the extra `choices` a caller may attach, and
    /// this dialog deliberately offers only allow and refuse — a permission
    /// prompt that also asks three side questions is one people stop reading.
    #[allow(clippy::too_many_arguments)]
    async fn access_dialog(
        &self,
        handle: ObjectPath<'_>,
        app_id: String,
        parent_window: String,
        title: String,
        subtitle: String,
        body: String,
        options: std::collections::HashMap<String, OwnedValue>,
    ) -> (u32, std::collections::HashMap<String, OwnedValue>) {
        // Named without underscores because the names travel: they appear in the
        // introspection the portal and anyone debugging it reads.
        //
        // `handle` would let the portal cancel a request; this dialog answers
        // quickly and closes itself, so there is nothing to cancel. The parent
        // window cannot be honoured either — Wayland gives a client no way to
        // place itself over another client's window.
        let _ = (handle, parent_window, options);

        let granted = crate::dialog::ask(
            &self.app,
            Question::Portal(PortalQuestion {
                app_id,
                title,
                subtitle,
                body,
            }),
        )
        .await;

        let response = if granted {
            RESPONSE_GRANTED
        } else {
            // Cancelled rather than a distinct "denied": the portal treats
            // anything other than success as not granted, and this is the code
            // it expects for a person who said no.
            RESPONSE_CANCELLED
        };

        (response, std::collections::HashMap::new())
    }

    /// Advertised so the portal knows what it is talking to. The portal checks
    /// this before using a backend.
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        1
    }
}

/// Claims the backend name on the session bus.
///
/// Separate from the connection the agent uses to reach the permission service:
/// that one is the *system* bus, and the portal only ever looks on the session
/// bus. One process, two buses, because the two jobs live in different places.
pub async fn serve(app: AppHandle) -> Result<zbus::Connection, String> {
    zbus::connection::Builder::session()
        .map_err(|e| format!("no se pudo abrir el bus de sesión: {e}"))?
        .name(BACKEND_NAME)
        .map_err(|e| format!("no se pudo tomar el nombre {BACKEND_NAME}: {e}"))?
        .serve_at(BACKEND_PATH, AccessBackend { app })
        .map_err(|e| format!("no se pudo publicar el backend del portal: {e}"))?
        .build()
        .await
        .map_err(|e| format!("no se pudo conectar al bus de sesión: {e}"))
}
