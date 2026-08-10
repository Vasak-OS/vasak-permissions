//! The window that asks, created only when there is something to ask.

use std::sync::{Arc, Mutex};

use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::oneshot;
use vasak_permissions_protocol::PermissionRequest;

const WINDOW_LABEL: &str = "permission-dialog";
const DIALOG_WIDTH: f64 = 460.0;
const DIALOG_HEIGHT: f64 = 320.0;

/// The question currently on screen and where to send the answer.
struct Pending {
    request: PermissionRequest,
    answer: Option<oneshot::Sender<bool>>,
}

#[derive(Clone, Default)]
pub struct DialogState {
    pending: Arc<Mutex<Option<Pending>>>,
}

/// Shows the question and waits for the person to answer it.
///
/// One question at a time: a second request while a dialog is open is refused
/// rather than queued or stacked. Two permission dialogs on screen at once is
/// how people click the wrong one, and the caller can always ask again.
pub async fn ask(app: &AppHandle, request: PermissionRequest) -> bool {
    let state = app.state::<DialogState>();
    let (sender, receiver) = oneshot::channel();

    {
        let mut pending = match state.pending.lock() {
            Ok(pending) => pending,
            Err(_) => return false,
        };
        if pending.is_some() {
            return false;
        }
        *pending = Some(Pending {
            request,
            answer: Some(sender),
        });
    }

    eprintln!(
        "[vasak-permissions-agent] consulta: {} pide '{}'",
        request_summary(&state),
        resource_of(&state)
    );

    if let Err(error) = open_window(app) {
        eprintln!("[vasak-permissions-agent] no se pudo abrir el diálogo: {error}");
        clear(app, false);
        return false;
    }

    // A closed window resolves to a refusal: dismissing a permission dialog
    // means no.
    receiver.await.unwrap_or(false)
}


/// Short description of what is on screen, for the journal. A permission
/// dialog that nobody can account for afterwards is hard to support.
fn request_summary(state: &tauri::State<'_, DialogState>) -> String {
    state
        .pending
        .lock()
        .ok()
        .and_then(|pending| {
            pending
                .as_ref()
                .map(|entry| entry.request.application.binary_path.clone())
        })
        .unwrap_or_default()
}

fn resource_of(state: &tauri::State<'_, DialogState>) -> String {
    state
        .pending
        .lock()
        .ok()
        .and_then(|pending| pending.as_ref().map(|entry| entry.request.resource_id.clone()))
        .unwrap_or_default()
}

fn open_window(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(WINDOW_LABEL) {
        window.show()?;
        window.set_focus()?;
        return Ok(());
    }

    let window = WebviewWindowBuilder::new(app, WINDOW_LABEL, WebviewUrl::default())
        .title("Permiso")
        .inner_size(DIALOG_WIDTH, DIALOG_HEIGHT)
        .resizable(false)
        .decorations(false)
        .transparent(true)
        // The dialog is about something happening now; it should not be lost
        // behind the window that triggered it.
        .center()
        .build()?;

    let handle = app.clone();
    window.on_window_event(move |event| {
        if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
            clear(&handle, false);
        }
    });

    Ok(())
}

/// Resolves whatever is pending and hides the window.
fn clear(app: &AppHandle, allowed: bool) {
    let state = app.state::<DialogState>();

    if let Ok(mut pending) = state.pending.lock() {
        if let Some(mut entry) = pending.take() {
            if let Some(sender) = entry.answer.take() {
                let _ = sender.send(allowed);
            }
        }
    }

    // Hidden rather than destroyed: rebuilding the webview for the next
    // question costs a second of staring at nothing, and one hidden window that
    // only exists after the first request is a fair trade.
    if let Some(window) = app.get_webview_window(WINDOW_LABEL) {
        let _ = window.hide();
    }
}

/// What the interface should display. `null` when nothing is pending.
#[tauri::command]
pub fn pending_request(state: tauri::State<'_, DialogState>) -> Option<PermissionRequest> {
    state
        .pending
        .lock()
        .ok()
        .and_then(|pending| pending.as_ref().map(|entry| entry.request.clone()))
}

#[tauri::command]
pub fn answer(app: AppHandle, allowed: bool) {
    clear(&app, allowed);
}
