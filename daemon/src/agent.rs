//! Keeping track of the dialog agents and putting questions to them.
//!
//! There is one agent per logged-in session and one service for the whole
//! machine, so the service has to know which agent belongs to which user.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use vasak_permissions_protocol::{
    PermissionRequest, AGENT_BINARY, AGENT_INTERFACE,
};

/// How long to wait for someone to answer the dialog.
///
/// Long enough to read it and think about it, short enough that a wedged agent
/// eventually releases the program waiting on the other end instead of hanging
/// it for the rest of the session.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

/// Lo que se espera por un aviso, que es otra cosa que una pregunta.
///
/// Una pregunta espera a que una persona lea y decida, y por eso se le dan dos
/// minutos. Un aviso no espera a nadie: si el agente no lo acusa en unos
/// segundos es que algo anda mal, y seguir esperando sólo retrasa el registro
/// del problema.
const TIEMPO_DE_AVISO: Duration = Duration::from_secs(10);

/// The unique bus name and object path of one registered agent.
#[derive(Clone)]
struct RegisteredAgent {
    unique_name: String,
    object_path: String,
}

#[derive(Default)]
pub struct AgentRegistry {
    by_uid: HashMap<u32, RegisteredAgent>,
}

pub type SharedAgents = Arc<Mutex<AgentRegistry>>;

impl AgentRegistry {
    /// Accepts a registration, provided the caller really is the agent.
    ///
    /// The check is the executable path, and it is the reason a hostile
    /// program cannot register itself and approve its own requests: writing to
    /// `/usr/bin` needs root, so nothing running as the user can occupy that
    /// path. Everything else about a connection — its name, what it claims —
    /// is under the caller's control and worth nothing here.
    pub fn register(
        &mut self,
        uid: u32,
        binary_path: &str,
        unique_name: String,
        object_path: String,
    ) -> Result<(), String> {
        if !is_the_agent(binary_path) {
            return Err(format!(
                "solo {AGENT_BINARY} puede actuar como agente de permisos; \
                 se rechazó {binary_path}"
            ));
        }

        // A later registration replaces the earlier one: the session's agent
        // may legitimately restart, and refusing would leave that user unable
        // to be asked anything until they log out.
        self.by_uid.insert(
            uid,
            RegisteredAgent {
                unique_name,
                object_path,
            },
        );
        Ok(())
    }

    /// Drops an agent whose connection went away, so the service stops trying
    /// to reach a name nobody owns.
    pub fn forget_connection(&mut self, unique_name: &str) {
        self.by_uid
            .retain(|_, agent| agent.unique_name != unique_name);
    }

    fn agent_for(&self, uid: u32) -> Option<RegisteredAgent> {
        self.by_uid.get(&uid).cloned()
    }
}


/// Whether this executable is the installed agent.
///
/// The comparison is against one absolute path and nothing else. Matching on
/// the file name, or on anything the caller controls, would let a program in
/// the user's home called `vasak-permissions-agent` register itself and
/// approve its own requests — which is the one thing this must prevent.
#[cfg(not(debug_assertions))]
fn is_the_agent(binary_path: &str) -> bool {
    binary_path == AGENT_BINARY
}

/// Debug builds also accept an agent that has not been installed yet, so the
/// dialog can be exercised from a working copy. Compiled out of release
/// entirely rather than guarded at runtime.
#[cfg(debug_assertions)]
fn is_the_agent(binary_path: &str) -> bool {
    if binary_path == AGENT_BINARY {
        return true;
    }

    std::env::var_os("VASAK_PERMISSIONS_TEST_ROOT").is_some()
        && std::path::Path::new(binary_path)
            .file_name()
            .is_some_and(|name| name == "vasak-permissions-agent")
}

/// Le avisa al usuario que AppArmor le negó un recurso a una aplicación.
///
/// No pregunta nada y no espera respuesta: el bloqueo ya ocurrió y no se puede
/// deshacer. Lo único que hace es que deje de ser invisible.
///
/// Si no hay agente corriendo, se pierde, y está bien: un aviso es útil en el
/// momento y no tiene sentido guardarlo para mostrarlo en el próximo inicio de
/// sesión, cuando la persona ya no se acuerda de qué estaba haciendo.
pub async fn avisar_de_bloqueo(
    connection: &zbus::Connection,
    agents: &SharedAgents,
    uid: u32,
    application: &vasak_permissions_protocol::Application,
    resource: &vasak_permissions_protocol::Resource,
) {
    let Some(agent) = agents.lock().await.agent_for(uid) else {
        tracing::debug!("Sin agente para el usuario {uid}; el aviso se descarta");
        return;
    };

    let aviso = PermissionRequest {
        application: application.clone(),
        resource_id: resource.as_id(),
        detail: String::new(),
    };
    let Ok(payload) = serde_json::to_string(&aviso) else {
        return;
    };

    let arguments = (payload.as_str(),);
    let call = connection.call_method(
        Some(agent.unique_name.as_str()),
        agent.object_path.as_str(),
        Some(AGENT_INTERFACE),
        "NotifyBlocked",
        &arguments,
    );
    // Los dos fallos posibles se registran, y a nivel `warn`.
    //
    // La primera versión de esto hacía `if let Err(_) = timeout(...)`, que sólo
    // atrapa que se acabe el tiempo: el error de la propia llamada de D-Bus
    // viene envuelto adentro del `Ok`, y se perdía en silencio. El resultado
    // fue un aviso que no aparecía y un servicio que decía haberlo mandado —
    // exactamente el fallo callado que este módulo existe para evitar—.
    match tokio::time::timeout(TIEMPO_DE_AVISO, call).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            tracing::warn!("El agente del usuario {uid} rechazó el aviso: {error}");
        }
        Err(_) => {
            tracing::warn!(
                "El agente del usuario {uid} no acusó el aviso en {}s",
                TIEMPO_DE_AVISO.as_secs()
            );
        }
    }
}

/// Puts a request to the user and returns their answer, or `None` when the
/// question could not be put to them at all.
///
/// The distinction matters more than it looks. Access is refused either way —
/// the safe answer to "we could not ask" is no — but only a real answer may be
/// remembered. Recording "no agent was running" as a refusal would permanently
/// deny anything that asked during login, before the dialog agent had started,
/// and the user would never be asked again.
pub async fn ask(
    connection: &zbus::Connection,
    agents: &SharedAgents,
    uid: u32,
    request: &PermissionRequest,
) -> Option<bool> {
    let Some(agent) = agents.lock().await.agent_for(uid) else {
        tracing::warn!(
            "No hay agente de permisos para el usuario {uid}; \
             se deniega '{}' a {}",
            request.resource_id,
            request.application.binary_path
        );
        return None;
    };

    let payload = match serde_json::to_string(request) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::error!("No se pudo serializar la consulta de permiso: {error}");
            return None;
        }
    };

    let arguments = (payload.as_str(),);
    let call = connection.call_method(
        Some(agent.unique_name.as_str()),
        agent.object_path.as_str(),
        Some(AGENT_INTERFACE),
        "RequestPermission",
        &arguments,
    );

    let reply = match tokio::time::timeout(ANSWER_TIMEOUT, call).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(error)) => {
            tracing::warn!(
                "El agente de permisos del usuario {uid} falló ({error}); \
                 se deniega '{}'",
                request.resource_id
            );
            return None;
        }
        Err(_) => {
            tracing::warn!(
                "El agente de permisos del usuario {uid} no respondió en {}s; \
                 se deniega '{}'",
                ANSWER_TIMEOUT.as_secs(),
                request.resource_id
            );
            return None;
        }
    };

    match reply.body().deserialize::<bool>() {
        Ok(answer) => Some(answer),
        Err(error) => {
            tracing::warn!("Respuesta inválida del agente de permisos: {error}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_installed_agent_binary_may_register() {
        let mut registry = AgentRegistry::default();

        // The whole security of the prompt rests on this: a program the user
        // can write could otherwise register and approve everything itself.
        assert!(registry
            .register(1000, "/home/someone/fake-agent", ":1.42".into(), "/x".into())
            .is_err());
        assert!(registry
            .register(1000, "/usr/bin/some-other-program", ":1.42".into(), "/x".into())
            .is_err());

        assert!(registry
            .register(1000, AGENT_BINARY, ":1.7".into(), "/x".into())
            .is_ok());
    }

    #[test]
    fn a_restarted_agent_replaces_the_previous_one() {
        let mut registry = AgentRegistry::default();
        registry
            .register(1000, AGENT_BINARY, ":1.7".into(), "/x".into())
            .expect("first");
        registry
            .register(1000, AGENT_BINARY, ":1.9".into(), "/x".into())
            .expect("after restart");

        assert_eq!(registry.agent_for(1000).unwrap().unique_name, ":1.9");
    }

    /// One service serves every session on the machine, so an answer must
    /// never be routed to somebody else's screen.
    #[test]
    fn each_user_gets_their_own_agent() {
        let mut registry = AgentRegistry::default();
        registry
            .register(1000, AGENT_BINARY, ":1.7".into(), "/x".into())
            .expect("first user");
        registry
            .register(1001, AGENT_BINARY, ":1.8".into(), "/x".into())
            .expect("second user");

        assert_eq!(registry.agent_for(1000).unwrap().unique_name, ":1.7");
        assert_eq!(registry.agent_for(1001).unwrap().unique_name, ":1.8");
        assert!(registry.agent_for(1002).is_none());
    }

    #[test]
    fn an_agent_that_disconnects_is_forgotten() {
        let mut registry = AgentRegistry::default();
        registry
            .register(1000, AGENT_BINARY, ":1.7".into(), "/x".into())
            .expect("register");

        registry.forget_connection(":1.7");

        assert!(
            registry.agent_for(1000).is_none(),
            "a stale name would make every later request wait for the timeout"
        );
    }
}
