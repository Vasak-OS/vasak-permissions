//! Core business logic for the permission service.
//!
//! This module contains the pure business logic separated from D-Bus transport.
//! It can be tested without a system bus or root privileges.

use std::sync::Arc;
use tokio::sync::Mutex;

use vasak_permissions_protocol::{
    Application, Decision, PermissionRequest, Provenance, Resource,
    SERVICE_INTERFACE, SERVICE_NAME, SERVICE_PATH,
};
use zbus::fdo::Error as FdoError;

use crate::{
    agent::{AgentRegistry, SharedAgents},
    audit,
    excepcion,
    identity,
    local,
    policy::PolicyStore,
    throttle::{NoticeThrottle, PromptThrottle},
    identity::PinnedCaller,
    local::Pendientes,
};

/// Core business logic for permission decisions.
/// 
/// This struct holds all the state needed for making permission decisions
/// but does NOT depend on D-Bus connections or the system bus.
/// It can be fully tested in isolation.
#[derive(Debug)]
#[derive(Debug)]
#[derive(Debug)]
pub struct PermissionCore {
    store: PolicyStore,
    agents: crate::agent::SharedAgents,
    write_lock: Arc<Mutex<()>>,
    throttle: Arc<Mutex<crate::throttle::PromptThrottle>>,
    notices: Arc<Mutex<crate::throttle::NoticeThrottle>>,
    pendientes: crate::local::Pendientes,
}

impl PermissionCore {
    /// Creates a new permission core with default configuration.
    pub fn new() -> Self {
        Self {
            store: PolicyStore::new(),
            agents: Arc::new(tokio::sync::Mutex::new(crate::agent::AgentRegistry::default())),
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            throttle: Arc::new(tokio::sync::Mutex::new(crate::throttle::PromptThrottle::default())),
            notices: Arc::new(tokio::sync::Mutex::new(crate::throttle::NoticeThrottle::default())),
            pendientes: crate::local::Pendientes::default(),
        }
    }

    /// Creates a core with custom components (useful for testing).
    pub fn with_components(
        store: crate::policy::PolicyStore,
        agents: crate::agent::SharedAgents,
        write_lock: Arc<tokio::sync::Mutex<()>>,
        throttle: Arc<tokio::sync::Mutex<crate::throttle::PromptThrottle>>,
        notices: Arc<tokio::sync::Mutex<crate::throttle::NoticeThrottle>>,
        pendientes: crate::local::Pendientes,
    ) -> Self {
        Self {
            store,
            agents,
            write_lock,
            throttle,
            notices,
            pendientes,
        }
    }

    /// Core decision logic: determines if a request should be allowed.
    /// 
    /// This is the pure business logic extracted from `decide`:
    /// 1. Checks scope (may_request)
    /// 2. Checks existing policy
    /// 3. Applies throttle
    /// 4. Asks agent (if available)
    /// 5. Records decision
    /// 
    /// Returns the decision and whether it was allowed.
    pub async fn decide(
        &self,
        connection: &zbus::Connection,
        subject: &crate::identity::PinnedCaller,
        resource_id: &str,
        detail: String,
    ) -> zbus::fdo::Result<bool> {
        let application = subject.describe();

        // Check scope first
        if !vasak_permissions_protocol::may_request(&application.binary_path, resource_id) {
            tracing::warn!(
                "OUT OF SCOPE — {} requested '{}', not in declared scope. Denied.",
                application.binary_path, resource_id
            );
            return Ok(false);
        }

        // Check existing policy
        let stored = self
            .store
            .load(subject.uid)
            .map_err(zbus::fdo::Error::Failed)?
            .decision(&application.binary_path, resource_id);

        let decision = match stored {
            vasak_permissions_protocol::Decision::Allowed | vasak_permissions_protocol::Decision::Denied => stored,
            vasak_permissions_protocol::Decision::Unknown => {
                // Apply throttle
                let within_ceiling = self
                    .throttle
                    .lock()
                    .await
                    .allow(subject.uid, std::time::Instant::now());

                if !within_ceiling {
                    tracing::warn!(
                        "THROTTLE — Too many permission requests; denying '{}' to {}",
                        resource_id, subject.binary_path()
                    );
                    return Ok(false);
                }

                // Ask the agent
                let request = PermissionRequest {
                    profile: String::new(),
                    application: application.clone(),
                    resource_id: resource_id.to_string(),
                    detail,
                };

                let Some(answer) =
                    crate::agent::ask(connection, &self.agents, subject.uid, &request).await
                else {
                    // No agent or agent failed
                    self.throttle.lock().await.refund(subject.uid);
                    return Ok(false);
                };

                // Record the decision
                let _guard = self.write_lock.lock().await;
                let mut policy = self.store.load(subject.uid).map_err(zbus::fdo::Error::Failed)?;
                policy.record(
                    &application,
                    resource_id,
                    vasak_permissions_protocol::Decision::from_answer(answer),
                    true, // asks = true since the program asked
                );
                self.store
                    .save(subject.uid, &policy)
                    .map_err(zbus::fdo::Error::Failed)?;

                vasak_permissions_protocol::Decision::from_answer(answer)
            }
        };

        if !decision.is_allowed() {
            tracing::info!(
                "DENIED '{}' to {} (PID {})",
                resource_id,
                subject.binary_path(),
                subject.pid
            );
        }

        Ok(decision.is_allowed())
    }

    /// Checks a resource against a key without making a decision.
    /// Used by query_permission_for and check_permission_for.
    pub fn check_resource(resource_id: &str, key: &str) -> zbus::fdo::Result<()> {
        use vasak_permissions_protocol::Resource;
        match Resource::from_id(resource_id) {
            Some(resource) if resource.decision_has_effect_for(key) => Ok(()),
            Some(_) => Err(zbus::fdo::Error::NotSupported(format!(
                "'{resource_id}' not enforceable for '{key}': provided by PipeWire or desktop portal, no profile denies it."
            ))),
            None => Err(zbus::fdo::Error::InvalidArgs(format!(
                "unknown resource: '{resource_id}'"
            ))),
        }
    }

    /// Checks if a resource is in scope for a binary path.
    pub fn may_request(binary_path: &str, resource_id: &str) -> bool {
        vasak_permissions_protocol::may_request(binary_path, resource_id)
    }

    /// Queries the stored decision without asking the user.
    /// Returns "allowed", "denied", or "unknown".
    pub async fn query_permission(
        &self,
        subject: &crate::identity::PinnedCaller,
        resource_id: &str,
    ) -> zbus::fdo::Result<String> {
        // Scope check
        if !Self::may_request(&subject.binary_path(), resource_id) {
            return Ok(vasak_permissions_protocol::Decision::Denied.as_id().to_string());
        }

        let stored = self
            .store
            .load(subject.uid)
            .map_err(zbus::fdo::Error::Failed)?
            .decision(&subject.binary_path(), resource_id);

        Ok(stored.as_id().to_string())
    }

    /// Records a decision from the settings screen (polkit-authorized).
    pub async fn set_permission(
        &self,
        caller_uid: u32,
        binary_path: &str,
        resource_id: &str,
        allowed: bool,
    ) -> zbus::fdo::Result<()> {
        // Scope check
        if allowed && !Self::may_request(binary_path, resource_id) {
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "{binary_path} cannot use '{resource_id}': outside declared scope."
            )));
        }

        let _guard = self.write_lock.lock().await;
        let mut policy = self.store.load(caller_uid).map_err(zbus::fdo::Error::Failed)?;

        let _application = crate::identity::describe_path(binary_path);

        // Portal keys have no AppArmor profile
        if vasak_permissions_protocol::is_portal_key(binary_path) {
            policy.record(
                &crate::identity::describe_path(binary_path),
                resource_id,
                vasak_permissions_protocol::Decision::from_answer(allowed),
                true,
            );
            return self.store.save(caller_uid, &policy)
                .map_err(zbus::fdo::Error::Failed);
        }

        let antes = excepcion::permitidos_de(&policy, binary_path);
        policy.record(
            &crate::identity::describe_path(binary_path),
            resource_id,
            vasak_permissions_protocol::Decision::from_answer(allowed),
            false,
        );
        let ahora = excepcion::permitidos_de(&policy, binary_path);

        // Apply AppArmor profile first
        if let Err(error) = excepcion::aplicar(binary_path, &ahora) {
            tracing::warn!("Failed to apply profile for {binary_path}: {error}");
            return Err(zbus::fdo::Error::Failed(format!(
                "decision not saved because profile apply failed: {error}"
            )));
        }

        if let Err(error) = self.store.save(caller_uid, &policy) {
            if let Err(otro) = excepcion::aplicar(binary_path, &antes) {
                tracing::error!(
                    "Failed to save decision for {binary_path} AND rollback profile failed ({otro}); system inconsistent"
                );
            }
            return Err(zbus::fdo::Error::Failed(error));
        }
        Ok(())
    }

    /// Forgets a permission entirely.
    pub async fn forget_permission(
        &self,
        caller_uid: u32,
        binary_path: &str,
    ) -> zbus::fdo::Result<()> {
        let _guard = self.write_lock.lock().await;
        let mut policy = self.store.load(caller_uid).map_err(zbus::fdo::Error::Failed)?;
        policy.forget(binary_path);
        self.store.save(caller_uid, &policy)
            .map_err(zbus::fdo::Error::Failed)
    }

    /// Gets the portal decision for an app_id.
    pub async fn portal_decision(
        &self,
        app_id: &str,
        resource_id: &str,
    ) -> zbus::fdo::Result<String> {
        let key = vasak_permissions_protocol::portal_key(app_id)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!(
                "'{app_id}' is not a valid app_id"
            )))?;
        Self::check_resource(resource_id, &key)?;

        let stored = self
            .store
            .load(0) // Portal decisions are stored under uid 0? No, need to check
            .map_err(zbus::fdo::Error::Failed)?
            .decision(&key, resource_id);

        Ok(stored.as_id().to_string())
    }

    /// Records a portal decision from the agent.
    pub async fn record_portal_decision(
        &self,
        app_id: &str,
        resource_id: &str,
        allowed: bool,
    ) -> zbus::fdo::Result<()> {
        let key = vasak_permissions_protocol::portal_key(app_id)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!(
                "'{app_id}' is not a valid app_id"
            )))?;
        Self::check_resource(resource_id, &key)?;

        let _guard = self.write_lock.lock().await;
        let mut policy = self.store.load(0).map_err(zbus::fdo::Error::Failed)?;

        let application = crate::identity::describe_path(&key);
        policy.record(
            &application,
            resource_id,
            vasak_permissions_protocol::Decision::from_answer(allowed),
            true, // asks = true for portal decisions
        );
        self.store.save(0, &policy)
            .map_err(zbus::fdo::Error::Failed)
    }

    /// Lists all blocked items for a user.
    pub async fn list_blocked(&self, uid: u32) -> zbus::fdo::Result<String> {
        let lista = crate::local::listar(&self.pendientes, uid);
        serde_json::to_string(&lista)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialization failed: {e}")))
    }

    /// Allows a blocked item.
    pub async fn allow_blocked(
        &self,
        caller_uid: u32,
        profile: &str,
        path: &str,
    ) -> zbus::fdo::Result<()> {
        let lista = crate::local::listar(&self.pendientes, caller_uid);
        let bloqueo = lista
            .into_iter()
            .find(|b| b.perfil == profile && b.ruta == path)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("blocked item not found".into()))?;

        let regla = crate::local::regla_para(&bloqueo.ruta, &bloqueo.mascara)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;

        let _guard = self.write_lock.lock().await;
        crate::local::conceder_y_recargar(&bloqueo.perfil, &regla, &crate::local::raiz())
            .map_err(zbus::fdo::Error::Failed)?;

        crate::local::quitar(&self.pendientes, caller_uid, profile, path);
        Ok(())
    }

    /// Dismisses a blocked item without allowing it.
    pub async fn dismiss_blocked(
        &self,
        caller_uid: u32,
        profile: &str,
        path: &str,
    ) -> zbus::fdo::Result<()> {
        crate::local::quitar(&self.pendientes, caller_uid, profile, path);
        Ok(())
    }

    /// Revokes an allowed blocked item.
    pub async fn revoke_blocked(
        &self,
        profile: &str,
        rule: &str,
    ) -> zbus::fdo::Result<()> {
        let _guard = self.write_lock.lock().await;
        crate::local::revocar_y_recargar(profile, rule, &crate::local::raiz())
            .map_err(zbus::fdo::Error::Failed)
    }

    /// Lists allowed rules for a profile.
    pub async fn list_allowed(&self, profile: &str) -> zbus::fdo::Result<String> {
        if !crate::local::perfil_valido(profile) {
            return Err(zbus::fdo::Error::InvalidArgs("invalid profile name".into()));
        }
        let reglas = crate::local::concedidas_en(profile, &crate::local::raiz());
        serde_json::to_string(&reglas)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialization failed: {e}")))
    }

    /// Gets the pending items for a user.
    pub fn pendientes(&self) -> &crate::local::Pendientes {
        &self.pendientes
    }

    /// Gets the policy store.
    pub fn store(&self) -> &PolicyStore {
        &self.store
    }

    /// Gets the agents registry.
    pub fn agents(&self) -> &crate::agent::SharedAgents {
        &self.agents
    }

    /// Gets the write lock.
    pub fn write_lock(&self) -> &Arc<Mutex<()>> {
        &self.write_lock
    }

    /// Gets the throttle.
    pub fn throttle(&self) -> &Arc<Mutex<crate::throttle::PromptThrottle>> {
        &self.throttle
    }

    /// Gets the notices throttle.
    pub fn notices(&self) -> &Arc<Mutex<crate::throttle::NoticeThrottle>> {
        &self.notices
    }
}

impl Default for PermissionCore {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a permission decision.
#[derive(Debug, Clone)]
pub struct DecisionResult {
    pub allowed: bool,
    pub decision: vasak_permissions_protocol::Decision,
    pub was_cached: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use vasak_permissions_protocol::{Application, Decision, Provenance, Resource};

    fn make_core() -> PermissionCore {
        PermissionCore::new()
    }

    #[tokio::test]
    async fn test_may_request() {
        assert!(PermissionCore::may_request("/usr/bin/test-app", "camera"));
        assert!(!PermissionCore::may_request("/usr/bin/vasak-file-manager", "camera"));
        assert!(PermissionCore::may_request("/usr/bin/vasak-file-manager", "account.drive"));
    }

    #[tokio::test]
    async fn test_check_resource_valid() {
        let result = PermissionCore::check_resource("camera", "/usr/bin/test-app");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_resource_unknown() {
        let result = PermissionCore::check_resource("unknown", "/usr/bin/test-app");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_check_resource_portal_key() {
        use vasak_permissions_protocol::portal_key;
        let key = portal_key("com.google.Chrome").unwrap();
        
        let result = PermissionCore::check_resource("camera", &key);
        assert!(result.is_ok());
        
        let result = PermissionCore::check_resource("store.contacts", &key);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_new_core() {
        let core = PermissionCore::new();
        assert!(core.store().load(0).is_ok());
    }
}