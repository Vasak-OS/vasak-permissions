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

mod audit;
mod excepcion;
mod agent;
mod identity;
mod policy;
mod polkit;
mod throttle;

use std::sync::Arc;

use tokio::sync::Mutex;
use zbus::fdo::{DBusProxy, Error as FdoError};
use zbus::message::Header;
use zbus::names::BusName;
use zbus::{interface, Connection};

use agent::{AgentRegistry, SharedAgents};
use identity::PinnedCaller;
use policy::PolicyStore;
use throttle::PromptThrottle;
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
    /// Ceiling on how many dialogs a person can be shown at once.
    throttle: Arc<Mutex<PromptThrottle>>,
}

/// Rejects anything this service cannot honour.
///
/// An unrecognised id is a bug or an attempt to litter the policy with entries
/// the settings screen can never show. A recognised one that nothing enforces
/// is worse: the person would be asked a question, the answer would be stored,
/// and it would change nothing — while looking exactly like a decision that
/// held.
fn check_resource(resource_id: &str) -> Result<(), FdoError> {
    match Resource::from_id(resource_id) {
        Some(resource) if resource.is_enforceable() => Ok(()),
        Some(_) => Err(FdoError::NotSupported(format!(
            "'{resource_id}' todavía no se puede hacer cumplir en VasakOS: \
             lo entrega PipeWire o el portal de escritorio, que no consultan \
             este servicio. No se guarda ninguna decisión al respecto."
        ))),
        None => Err(FdoError::InvalidArgs(format!(
            "recurso desconocido: '{resource_id}'"
        ))),
    }
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


impl PermissionService {
    /// Looks up the stored answer, asks the user when there is none, and
    /// remembers what they said.
    async fn decide(
        &self,
        connection: &Connection,
        subject: &PinnedCaller,
        resource_id: &str,
        detail: String,
    ) -> zbus::fdo::Result<bool> {
        let application = subject.describe();

        let stored = self
            .store
            .load(subject.uid)
            .map_err(FdoError::Failed)?
            .decision(&application.binary_path, resource_id);

        let decision = match stored {
            Decision::Allowed | Decision::Denied => stored,
            Decision::Unknown => {
                // Refuse without asking once the person has been shown enough
                // dialogs at once. Nothing is recorded: a burst of noise must
                // not permanently deny a program whose dialog was never seen.
                let within_ceiling = self
                    .throttle
                    .lock()
                    .await
                    .allow(subject.uid, std::time::Instant::now());

                if !within_ceiling {
                    tracing::warn!(
                        "Demasiadas consultas de permiso seguidas; se deniega \
                         '{resource_id}' a {} sin preguntar",
                        application.binary_path
                    );
                    return Ok(false);
                }

                let request = PermissionRequest {
                    application: application.clone(),
                    resource_id: resource_id.to_string(),
                    detail,
                };

                let Some(answer) =
                    agent::ask(connection, &self.agents, subject.uid, &request).await
                else {
                    // The question could not be put to anyone — no agent yet,
                    // or it never answered. Refuse, but remember nothing:
                    // recording this would deny anything that asked during
                    // login for good, and the user would never see a dialog.
                    // Give the slot back too, since no dialog was displayed.
                    self.throttle.lock().await.refund(subject.uid);
                    return Ok(false);
                };

                // A real answer is remembered, refusals included. Storing
                // nothing would re-open the same dialog on the program's very
                // next attempt, and the person could never settle it.
                let _guard = self.write_lock.lock().await;
                let mut policy = self.store.load(subject.uid).map_err(FdoError::Failed)?;
                policy.record(&application, resource_id, Decision::from_answer(answer));
                self.store
                    .save(subject.uid, &policy)
                    .map_err(FdoError::Failed)?;

                Decision::from_answer(answer)
            }
        };

        if !decision.is_allowed() {
            tracing::info!(
                "Denegado '{resource_id}' a {} (PID {})",
                application.binary_path,
                subject.pid
            );
        }

        Ok(decision.is_allowed())
    }
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
        check_resource(&resource_id)?;

        let caller = caller_of(connection, &header).await?;
        self.decide(connection, &caller, &resource_id, detail).await
    }

    /// The same question, asked by a service on behalf of the program that
    /// called *it*.
    ///
    /// Needed because an application does not reach this service directly for an
    /// online account: it asks the account service, which then has to ask here.
    /// Without naming the original program, every application would share one
    /// decision recorded against the account service — which is no decision.
    ///
    /// Only the delegates listed in the protocol may call this, identified the
    /// same way as anyone else: by the executable behind their pinned PID.
    async fn check_permission_for(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        subject_pid: u32,
        subject_start_time: u64,
        resource_id: String,
        detail: String,
    ) -> zbus::fdo::Result<bool> {
        check_resource(&resource_id)?;

        let delegate = caller_of(connection, &header).await?;
        if !vasak_permissions_protocol::is_delegate(&delegate.binary_path()) {
            return Err(FdoError::AccessDenied(format!(
                "{} no puede consultar permisos en nombre de otro proceso",
                delegate.binary_path()
            )));
        }

        let subject = PinnedCaller::capture_subject(subject_pid, subject_start_time)
            .map_err(FdoError::InvalidArgs)?;

        // A delegate must not be able to ask about a process belonging to
        // somebody else, or one user's answer would be recorded in another
        // user's policy.
        if subject.uid != delegate.uid {
            return Err(FdoError::AccessDenied(
                "el proceso indicado pertenece a otro usuario".into(),
            ));
        }

        self.decide(connection, &subject, &resource_id, detail).await
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
        check_resource(&resource_id)?;

        let caller = caller_of(connection, &header).await?;
        polkit::authorize(connection, &caller).await?;

        let _guard = self.write_lock.lock().await;
        let mut policy = self.store.load(caller.uid).map_err(FdoError::Failed)?;

        // Describe the target program from the path being managed, not from
        // the caller: the settings screen is editing somebody else's entry.
        let application = identity::describe_path(&binary_path);
        // Lo que estaba concedido antes, para poder volver atrás si el guardado
        // falla después de haber tocado el perfil.
        let antes = excepcion::permitidos_de(&policy, &binary_path);
        policy.record(&application, &resource_id, Decision::from_answer(allowed));
        let ahora = excepcion::permitidos_de(&policy, &binary_path);

        // Primero el perfil, después el archivo de decisiones.
        //
        // El orden no es indiferente y las dos formas de fallar son distintas.
        // Guardando primero, un fallo al aplicar dejaría una decisión escrita
        // que el sistema no cumple: quien la tomó creería que la cámara quedó
        // permitida —o negada— y no sería cierto.
        //
        // Aplicando primero, un fallo deja todo como estaba y el error llega a
        // quien pidió el cambio, que es lo que corresponde. Y si lo que falla
        // es el guardado, se deshace el perfil para que el kernel y el disco no
        // queden diciendo cosas distintas.
        if let Err(error) = excepcion::aplicar(&binary_path, &ahora) {
            tracing::warn!("No se pudo aplicar el perfil de {binary_path}: {error}");
            return Err(FdoError::Failed(format!(
                "la decisión no se guardó porque no se pudo aplicar: {error}"
            )));
        }

        if let Err(error) = self.store.save(caller.uid, &policy) {
            if let Err(otro) = excepcion::aplicar(&binary_path, &antes) {
                // Deshacer también falló. Se registra fuerte: el perfil quedó
                // en un estado que el archivo de decisiones no describe.
                tracing::error!(
                    "No se pudo guardar la decisión de {binary_path} ni deshacer \
                     el perfil ({otro}); el sistema quedó inconsistente"
                );
            }
            return Err(FdoError::Failed(error));
        }
        Ok(())
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

    // El vigilante del registro del kernel también anota decisiones, así que
    // comparte el almacén y —sobre todo— el mismo candado de escritura: son dos
    // escritores sobre el mismo archivo.
    let store = PolicyStore::from_environment();
    let write_lock = Arc::new(Mutex::new(()));
    let store_para_el_vigilante = store.clone();
    let write_lock_para_el_vigilante = Arc::clone(&write_lock);

    let service = PermissionService {
        store,
        agents: Arc::clone(&agents),
        write_lock,
        throttle: Arc::new(Mutex::new(PromptThrottle::default())),
    };

    let connection = service_bus()?
        .name(SERVICE_NAME)?
        .serve_at(SERVICE_PATH, service)?
        .build()
        .await?;

    tokio::spawn(watch_for_departed_agents(connection.clone(), agents.clone()));
    // Avisa de lo que los perfiles de AppArmor bloquean. Sin esto, el bloqueo
    // es correcto pero invisible: se ve una cámara que no anda y nadie sabe por
    // qué.
    tokio::spawn(audit::vigilar(
        connection.clone(),
        agents,
        store_para_el_vigilante,
        write_lock_para_el_vigilante,
    ));

    tracing::info!("{SERVICE_NAME} escuchando en {SERVICE_PATH} ({SERVICE_INTERFACE})");
    std::future::pending::<()>().await;
    Ok(())
}
