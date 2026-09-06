//! Talking to the permission service.
//!
//! The agent connects **out** to the system bus and registers itself, and the
//! service calls back on that same connection. Going in this direction means
//! the service never has to reach into a user's session bus, and it can check
//! who is registering by looking at the connection it already has.

use tauri::{AppHandle, Manager};
use vasak_permissions_protocol::{
    PermissionRequest, AGENT_INTERFACE, SERVICE_INTERFACE, SERVICE_NAME, SERVICE_PATH,
};
use zbus::interface;

const AGENT_PATH: &str = "/ar/net/vasak/os/PermissionAgent";

/// Retry pacing for the initial registration.
///
/// The session can come up before the system service is ready, and an agent
/// that gave up would leave the user unable to be asked anything for the rest
/// of the session — every request would be refused with no dialog.
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(3);
const MAX_ATTEMPTS: u32 = 20;

struct Agent {
    app: AppHandle,
    /// Los avisos que están en pantalla con botones, y qué decide cada uno.
    avisados: crate::aviso::Avisados,
}

#[interface(name = "ar.net.vasak.os.PermissionAgent")]
impl Agent {
    /// Puts a question to the user and returns their answer.
    ///
    /// The request arrives as JSON so the shape of it lives in one place — the
    /// shared protocol crate — instead of being spelled out again as a D-Bus
    /// signature on each side.
    async fn request_permission(&self, request: String) -> zbus::fdo::Result<bool> {
        let request: PermissionRequest = serde_json::from_str(&request).map_err(|error| {
            zbus::fdo::Error::InvalidArgs(format!("consulta de permiso inválida: {error}"))
        })?;

        Ok(crate::dialog::ask(&self.app, crate::dialog::Question::Permission(request)).await)
    }

    /// Avisa que AppArmor le negó un recurso a una aplicación.
    ///
    /// No pregunta: el bloqueo ya ocurrió. Devuelve enseguida y muestra el
    /// aviso aparte, para que el servicio —que está leyendo el registro del
    /// kernel— no quede esperando a que aparezca una notificación.
    async fn notify_blocked(&self, aviso: String) -> zbus::fdo::Result<()> {
        let aviso: PermissionRequest = serde_json::from_str(&aviso).map_err(|error| {
            zbus::fdo::Error::InvalidArgs(format!("aviso de bloqueo inválido: {error}"))
        })?;

        // Este método está expuesto en el bus del sistema, así que en principio
        // lo puede llamar cualquier proceso local, no sólo el servicio de
        // permisos. Sin esta comprobación, alguien podría hacer aparecer un
        // aviso de VasakOS con el texto y el icono que quisiera.
        //
        // Se aceptan sólo los dos recursos que los perfiles de AppArmor niegan,
        // que son los únicos de los que este aviso sabe hablar.
        if !crate::aviso::se_avisa_de(&aviso.resource_id) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "no se avisa de bloqueos de '{}'",
                aviso.resource_id
            )));
        }

        let app = self.app.clone();
        let avisados = self.avisados.clone();
        tauri::async_runtime::spawn(
            async move { crate::aviso::mostrar(&app, &aviso, &avisados).await },
        );
        Ok(())
    }
}


/// The system bus, always, in a released build.
///
/// Debug builds follow the service onto a session bus so the dialog can be
/// exercised without installing anything. Compiled out of release entirely:
/// an agent that could be pointed at a bus the user controls would be
/// answering to something other than the permission service.
#[cfg(debug_assertions)]
fn service_bus() -> zbus::Result<zbus::connection::Builder<'static>> {
    if std::env::var_os("VASAK_PERMISSIONS_TEST_ROOT").is_some() {
        return zbus::connection::Builder::session();
    }
    zbus::connection::Builder::system()
}

#[cfg(not(debug_assertions))]
fn service_bus() -> zbus::Result<zbus::connection::Builder<'static>> {
    zbus::connection::Builder::system()
}

pub async fn connect_and_register(app: AppHandle) -> Result<(), String> {
    let avisados: crate::aviso::Avisados = Default::default();

    let connection = service_bus()
        .map_err(|e| format!("no se pudo abrir el bus del sistema: {e}"))?
        .serve_at(
            AGENT_PATH,
            Agent { app: app.clone(), avisados: avisados.clone() },
        )
        .map_err(|e| format!("no se pudo publicar el agente: {e}"))?
        .build()
        .await
        .map_err(|e| format!("no se pudo conectar al bus del sistema: {e}"))?;

    // Los botones del aviso: la señal llega por el bus de **sesión** y lo que
    // hay que llamar vive en el del sistema, así que la escucha necesita las
    // dos conexiones. Si no se puede suscribir, los botones no hacen nada y
    // Configuración sigue siendo la vía — por eso no se aborta el arranque.
    if let Ok(sesion) = zbus::Connection::session().await {
        let sistema = connection.clone();
        let avisados = avisados.clone();
        tauri::async_runtime::spawn(crate::aviso::escuchar_botones(sesion, sistema, avisados));
    }

    // Held by the app for as long as it runs. Dropping it would close the
    // connection, and the service would be left calling back on a name that no
    // longer exists — so every later request would time out into a refusal.
    app.manage(connection.clone());

    let mut last_error = String::new();
    for attempt in 0..MAX_ATTEMPTS {
        match register(&connection).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = error;
                if attempt + 1 < MAX_ATTEMPTS {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    }

    Err(format!(
        "no se pudo registrar tras {MAX_ATTEMPTS} intentos: {last_error}"
    ))
}

async fn register(connection: &zbus::Connection) -> Result<(), String> {
    let arguments = (AGENT_PATH,);
    connection
        .call_method(
            Some(SERVICE_NAME),
            SERVICE_PATH,
            Some(SERVICE_INTERFACE),
            "RegisterAgent",
            &arguments,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Kept so the interface name cannot drift from the protocol crate without the
/// compiler noticing.
const _: () = {
    assert!(matches!(AGENT_INTERFACE.as_bytes(), b"ar.net.vasak.os.PermissionAgent"));
};
