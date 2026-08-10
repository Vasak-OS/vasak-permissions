//! The VasakOS permission service.
//!
//! Answers one question — "may this program use this?" — for cameras,
//! microphones, screen capture and the user's online accounts alike, and
//! remembers what the person answered.
//!
//! It runs as root on the system bus for two reasons that admit no
//! alternative: identifying a caller means reading `/proc/<pid>/exe` of a
//! process that is not ours, and the stored answers have to live somewhere the
//! user's own programs cannot rewrite. A service inside the session could do
//! neither, which is exactly why the online-accounts list it replaces was
//! decorative — anyone could edit the file and grant themselves anything.

mod agent;
mod identity;
mod policy;
mod polkit;

use std::sync::Arc;

use tokio::sync::Mutex;
use zbus::fdo::{DBusProxy, Error as FdoError};
use zbus::message::Header;
use zbus::names::BusName;
use zbus::{interface, Connection};

use agent::{AgentRegistry, SharedAgents};
use identity::PinnedCaller;
use policy::PolicyStore;
use vasak_permissions_protocol::{
    Decision, PermissionRequest, Resource, SERVICE_INTERFACE, SERVICE_NAME, SERVICE_PATH,
};

struct PermissionService {
    store: PolicyStore,
    agents: SharedAgents,
    /// Serialises the read-modify-write of a policy file. Two programs asking
    /// at the same moment would otherwise each load the file, record their own
    /// answer and write it back, and whichever finished last would erase the
    /// other's decision.
    write_lock: Arc<Mutex<()>>,
}

/// Pins the caller of the current message and resolves who it is.
async fn caller_of(
    connection: &Connection,
    header: &Header<'_>,
) -> Result<PinnedCaller, FdoError> {
    let sender = header
        .sender()
        .ok_or_else(|| FdoError::Failed("el mensaje no tiene remitente".into()))?;

    let proxy = DBusProxy::new(connection)
        .await
        .map_err(|e| FdoError::Failed(format!("no se pudo consultar al bus: {e}")))?;

    let name = BusName::from(sender.clone());
    let pid = proxy
        .get_connection_unix_process_id(name.clone())
        .await
        .map_err(|e| FdoError::Failed(format!("no se pudo obtener el PID de {sender}: {e}")))?;
    let uid = proxy
        .get_connection_unix_user(name)
        .await
        .map_err(|e| FdoError::Failed(format!("no se pudo obtener el usuario de {sender}: {e}")))?;

    // Pin immediately: between the bus telling us the PID and us reading its
    // executable, the process could exit and its number be handed to another.
    PinnedCaller::capture(pid, uid).map_err(FdoError::Failed)
}

#[interface(name = "ar.net.vasak.os.Permissions")]
impl PermissionService {
    /// Whether the calling program may use `resource_id`, asking the user the
    /// first time and remembering the answer.
    ///
    /// `detail` carries context for the dialog — for an online account, which
    /// account is being asked for. It never affects the stored decision, so a
    /// program cannot get a second, differently-worded question by changing it.
    async fn check_permission(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        resource_id: String,
        detail: String,
    ) -> zbus::fdo::Result<bool> {
        // Reject ids the service does not know rather than storing them: an
        // unrecognised resource is a bug or an attempt to litter the policy
        // with entries the settings screen can never show or undo.
        if Resource::from_id(&resource_id).is_none() {
            return Err(FdoError::InvalidArgs(format!(
                "recurso desconocido: '{resource_id}'"
            )));
        }

        let caller = caller_of(connection, &header).await?;
        let application = caller.describe();

        let stored = self
            .store
            .load(caller.uid)
            .map_err(FdoError::Failed)?
            .decision(&application.binary_path, &resource_id);

        let decision = match stored {
            Decision::Allowed | Decision::Denied => stored,
            Decision::Unknown => {
                let request = PermissionRequest {
                    application: application.clone(),
                    resource_id: resource_id.clone(),
                    detail,
                };

                let answer =
                    agent::ask(connection, &self.agents, caller.uid, &request).await;

                // Record the refusal too. Storing nothing would re-open the
                // same dialog on the program's very next attempt, and the
                // person would have no way to settle it.
                let _guard = self.write_lock.lock().await;
                let mut policy = self.store.load(caller.uid).map_err(FdoError::Failed)?;
                policy.record(&application, &resource_id, Decision::from_answer(answer));
                self.store
                    .save(caller.uid, &policy)
                    .map_err(FdoError::Failed)?;

                Decision::from_answer(answer)
            }
        };

        if !decision.is_allowed() {
            tracing::info!(
                "Denegado '{resource_id}' a {} (PID {})",
                application.binary_path,
                caller.pid
            );
        }

        Ok(decision.is_allowed())
    }

    /// Everything decided for the calling user, as JSON, for the settings
    /// screen. A caller only ever sees its own user's policy.
    async fn list_permissions(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let caller = caller_of(connection, &header).await?;
        let policy = self.store.load(caller.uid).map_err(FdoError::Failed)?;

        serde_json::to_string(&policy.entries())
            .map_err(|e| FdoError::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Grants or revokes a permission from the settings screen.
    ///
    /// Behind polkit, and that is not a formality: without it any program could
    /// call this and grant itself what it had just been refused, which would
    /// make the entire service decorative.
    async fn set_permission(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        binary_path: String,
        resource_id: String,
        allowed: bool,
    ) -> zbus::fdo::Result<()> {
        if Resource::from_id(&resource_id).is_none() {
            return Err(FdoError::InvalidArgs(format!(
                "recurso desconocido: '{resource_id}'"
            )));
        }

        let caller = caller_of(connection, &header).await?;
        polkit::authorize(connection, &caller).await?;

        let _guard = self.write_lock.lock().await;
        let mut policy = self.store.load(caller.uid).map_err(FdoError::Failed)?;

        // Describe the target program from the path being managed, not from
        // the caller: the settings screen is editing somebody else's entry.
        let application = identity::describe_path(&binary_path);
        policy.record(&application, &resource_id, Decision::from_answer(allowed));

        self.store.save(caller.uid, &policy).map_err(FdoError::Failed)
    }

    /// Forgets a program entirely, so the next time it asks the user is asked
    /// again. Also behind polkit.
    async fn forget_permission(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        binary_path: String,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_of(connection, &header).await?;
        polkit::authorize(connection, &caller).await?;

        let _guard = self.write_lock.lock().await;
        let mut policy = self.store.load(caller.uid).map_err(FdoError::Failed)?;
        policy.forget(&binary_path);

        self.store.save(caller.uid, &policy).map_err(FdoError::Failed)
    }

    /// Offers this connection as the dialog agent for the calling user.
    ///
    /// Accepted only from the installed agent binary — see `AgentRegistry`.
    async fn register_agent(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        object_path: String,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_of(connection, &header).await?;
        let sender = header
            .sender()
            .ok_or_else(|| FdoError::Failed("el mensaje no tiene remitente".into()))?
            .to_string();

        self.agents
            .lock()
            .await
            .register(caller.uid, &caller.binary_path(), sender, object_path)
            .map_err(FdoError::AccessDenied)?;

        tracing::info!("Agente de permisos registrado para el usuario {}", caller.uid);
        Ok(())
    }
}

/// Drops agents whose connection has gone, so a later request fails fast
/// instead of waiting out the answer timeout against a name nobody owns.
async fn watch_for_departed_agents(connection: Connection, agents: SharedAgents) {
    use futures_util::StreamExt;

    let proxy = match DBusProxy::new(&connection).await {
        Ok(proxy) => proxy,
        Err(error) => {
            tracing::error!("No se pudo vigilar el bus: {error}");
            return;
        }
    };

    let mut changes = match proxy.receive_name_owner_changed().await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::error!("No se pudo escuchar NameOwnerChanged: {error}");
            return;
        }
    };

    while let Some(signal) = changes.next().await {
        let Ok(args) = signal.args() else { continue };
        // An empty new owner means the name went away.
        if args.new_owner().is_none() {
            agents.lock().await.forget_connection(args.name());
        }
    }
}

/// The system bus, always, in a released build.
///
/// Debug builds can be pointed at a session bus to exercise the service
/// without root. The escape hatch is compiled out of release entirely rather
/// than guarded at runtime: a permission service that could be moved onto a
/// bus the user controls would be no service at all.
#[cfg(debug_assertions)]
fn service_bus() -> zbus::Result<zbus::connection::Builder<'static>> {
    if std::env::var_os("VASAK_PERMISSIONS_TEST_ROOT").is_some() {
        tracing::warn!("MODO DE DESARROLLO: usando el bus de sesión");
        return zbus::connection::Builder::session();
    }
    zbus::connection::Builder::system()
}

#[cfg(not(debug_assertions))]
fn service_bus() -> zbus::Result<zbus::connection::Builder<'static>> {
    zbus::connection::Builder::system()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let agents: SharedAgents = Arc::new(Mutex::new(AgentRegistry::default()));

    let service = PermissionService {
        store: PolicyStore::from_environment(),
        agents: Arc::clone(&agents),
        write_lock: Arc::new(Mutex::new(())),
    };

    let connection = service_bus()?
        .name(SERVICE_NAME)?
        .serve_at(SERVICE_PATH, service)?
        .build()
        .await?;

    tokio::spawn(watch_for_departed_agents(connection.clone(), agents));

    tracing::info!("{SERVICE_NAME} escuchando en {SERVICE_PATH} ({SERVICE_INTERFACE})");
    std::future::pending::<()>().await;
    Ok(())
}
