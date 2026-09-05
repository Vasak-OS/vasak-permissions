//! The contract between the permission service, the dialog agent and the
//! settings interface.
//!
//! Everything that travels over D-Bus is defined here once so the three sides
//! cannot drift apart: a field renamed on one end stops compiling on the other
//! instead of silently becoming a permission that never matches.

use serde::{Deserialize, Serialize};

// ── Bus addresses ───────────────────────────────────────────────────────────

/// The service runs on the **system** bus, as root.
///
/// It has to read `/proc/<pid>/exe` of arbitrary processes to know who is
/// asking, which an unprivileged process cannot do for someone else's
/// processes, and it has to own a policy file the user's own programs cannot
/// rewrite. A service in the user's session could do neither.
pub const SERVICE_NAME: &str = "ar.net.vasak.os.Permissions";
pub const SERVICE_PATH: &str = "/ar/net/vasak/os/Permissions";
pub const SERVICE_INTERFACE: &str = "ar.net.vasak.os.Permissions";

/// The dialog agent, on the session bus of whoever is logged in.
pub const AGENT_INTERFACE: &str = "ar.net.vasak.os.PermissionAgent";

/// The only executable accepted as the dialog agent.
///
/// This is the whole reason a malicious program cannot register itself as the
/// agent and approve everything on its own behalf: writing to `/usr/bin`
/// requires root, so no program running as you can occupy this path.
pub const AGENT_BINARY: &str = "/usr/bin/vasak-permissions-agent";

/// polkit action guarding every change made from the settings interface.
///
/// Without it, any program could call `SetPermission` and grant itself what it
/// was just refused — which would make the whole service decorative.
pub const MANAGE_ACTION: &str = "ar.net.vasak.os.permissions.manage";


/// Services allowed to ask on behalf of somebody else.
///
/// An application does not talk to the permission service directly for an
/// online account — it talks to the account service, which then has to ask. If
/// that second hop asked in its own name, every application would end up
/// sharing one decision recorded against the account service, which is no
/// decision at all.
///
/// So a delegate names the process it is acting for. The list is absolute
/// paths under `/usr/bin`, which needs root to write: a program the user can
/// write cannot be one of these, and therefore cannot claim to be asking for
/// somebody else.
pub const DELEGATE_BINARIES: [&str; 1] = ["/usr/bin/vasak-accounts"];

#[cfg(not(debug_assertions))]
pub fn is_delegate(binary_path: &str) -> bool {
    DELEGATE_BINARIES.contains(&binary_path)
}

/// Debug builds also accept a delegate that has not been installed yet, so the
/// chain can be exercised from a working copy. Compiled out of release
/// entirely rather than guarded at runtime.
#[cfg(debug_assertions)]
pub fn is_delegate(binary_path: &str) -> bool {
    if DELEGATE_BINARIES.contains(&binary_path) {
        return true;
    }

    std::env::var_os("VASAK_PERMISSIONS_TEST_ROOT").is_some()
        && DELEGATE_BINARIES.iter().any(|installed| {
            std::path::Path::new(installed).file_name()
                == std::path::Path::new(binary_path).file_name()
        })
}

// ── Resources ───────────────────────────────────────────────────────────────

/// Something an application can ask to use.
///
/// Deliberately open-ended: hardware and online accounts share one model, so a
/// new resource is a new variant and everything else — storage, the dialog, the
/// settings list — already handles it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Resource {
    Camera,
    Microphone,
    /// Recording or capturing the screen.
    ScreenCapture,
    Location,
    /// Reading the keyboard globally: keyloggers and global shortcuts alike.
    InputCapture,
    /// Access to one capability of the user's online accounts.
    #[serde(rename = "account")]
    Account(AccountResource),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountResource {
    Email,
    Calendar,
    Contacts,
    Chat,
    Drive,
    Tasks,
}

impl Resource {
    /// Whether refusing this actually stops anything.
    ///
    /// Online accounts are handed out by a service that asks before answering,
    /// so a refusal is enforced.
    ///
    /// The camera and the microphone are now **partly** enforced, which is why
    /// this still answers no for them. An AppArmor profile denies the device
    /// nodes to applications the system did not install, and this service
    /// writes a per-application exception when somebody allows one. But that
    /// only covers the direct route: a program that asks PipeWire instead of
    /// opening the device — which is what modern applications do — is still not
    /// stopped, and neither is a program no profile covers, such as anything
    /// the package manager installed.
    ///
    /// Saying yes here would overstate it. Whoever asks this question wants to
    /// know whether a refusal can be relied upon, and for those two it cannot
    /// be yet.
    ///
    /// The screen, the location and the keyboard are handed out by PipeWire and
    /// the desktop portal, and neither consults this policy: a program that
    /// goes straight to them is not stopped, and the portal cannot even say
    /// which program is asking — the identity it passes on is empty for
    /// anything outside a sandbox.
    ///
    /// Requests for the rest are refused outright rather than remembered. A
    /// decision that changes nothing, and that the settings screen therefore
    /// does not show, would be worse than no decision: the person could neither
    /// rely on it nor take it back.
    pub fn is_enforceable(&self) -> bool {
        matches!(self, Resource::Account(_))
    }

    /// Whether deciding this changes anything at all.
    ///
    /// A different question from [`Self::is_enforceable`], and mixing the two
    /// kept the camera switch from working: that one asks whether a refusal can
    /// be *relied upon*, and for the camera it cannot yet, because a program can
    /// still ask PipeWire. This one asks whether the decision has any effect —
    /// and it does: the service writes an AppArmor exception, so allowing gives
    /// a confined application access it did not have, and removing takes it
    /// away.
    ///
    /// Storing a decision that changes nothing would be worse than refusing it,
    /// which is why the distinction exists at all. But refusing one that *does*
    /// change something leaves a switch that cannot be moved.
    pub fn decision_has_effect(&self) -> bool {
        matches!(
            self,
            Resource::Account(_) | Resource::Camera | Resource::Microphone
        )
    }

    /// Stable text form used on the bus and in the stored policy.
    ///
    /// Spelled out by hand rather than derived, because these strings end up in
    /// a file on disk: a refactor that renamed a variant would otherwise
    /// silently invalidate every decision the user had already made.
    pub fn as_id(&self) -> String {
        match self {
            Resource::Camera => "camera".into(),
            Resource::Microphone => "microphone".into(),
            Resource::ScreenCapture => "screen-capture".into(),
            Resource::Location => "location".into(),
            Resource::InputCapture => "input-capture".into(),
            Resource::Account(capability) => format!("account.{}", capability.as_id()),
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        if let Some(capability) = id.strip_prefix("account.") {
            return AccountResource::from_id(capability).map(Resource::Account);
        }

        match id {
            "camera" => Some(Resource::Camera),
            "microphone" => Some(Resource::Microphone),
            "screen-capture" => Some(Resource::ScreenCapture),
            "location" => Some(Resource::Location),
            "input-capture" => Some(Resource::InputCapture),
            _ => None,
        }
    }
}

impl AccountResource {
    pub fn as_id(&self) -> &'static str {
        match self {
            AccountResource::Email => "email",
            AccountResource::Calendar => "calendar",
            AccountResource::Contacts => "contacts",
            AccountResource::Chat => "chat",
            AccountResource::Drive => "drive",
            AccountResource::Tasks => "tasks",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "email" => Some(AccountResource::Email),
            "calendar" => Some(AccountResource::Calendar),
            "contacts" => Some(AccountResource::Contacts),
            "chat" => Some(AccountResource::Chat),
            "drive" => Some(AccountResource::Drive),
            "tasks" => Some(AccountResource::Tasks),
            _ => None,
        }
    }
}

// ── Decisions ───────────────────────────────────────────────────────────────

/// What the stored policy says about one application and one resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Allowed,
    Denied,
    /// Never decided, so the user has to be asked.
    Unknown,
}

impl Decision {
    pub fn from_answer(allowed: bool) -> Self {
        if allowed {
            Decision::Allowed
        } else {
            Decision::Denied
        }
    }

    pub fn is_allowed(self) -> bool {
        matches!(self, Decision::Allowed)
    }
}

// ── Applications ────────────────────────────────────────────────────────────

/// How much the service can vouch for the identity of a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provenance {
    /// Installed under a path only root can write, so the binary behind a
    /// remembered decision cannot have been swapped for another one.
    SystemInstalled,
    /// Anywhere the user can write: their own scripts, a downloaded AppImage.
    /// The decision is still honoured, but the dialog says so — the same thing
    /// macOS means by an unidentified developer.
    Unverified,
}

/// A program asking for something, as the service sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    /// Absolute, symlink-resolved path to the executable. This is the identity
    /// a decision is recorded against.
    pub binary_path: String,
    /// Name to show a person, resolved from the desktop entry when there is
    /// one and falling back to the file name.
    pub display_name: String,
    pub provenance: Provenance,
}

/// One stored decision, as listed by the settings interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEntry {
    pub application: Application,
    /// Resource ids (`Resource::as_id`) mapped to what was decided.
    pub decisions: std::collections::BTreeMap<String, Decision>,
}

/// What the agent is asked to put to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub application: Application,
    pub resource_id: String,
    /// Extra context for account resources: which account is being asked for.
    /// Empty for hardware resources.
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These strings are written to disk. If a rename ever changes one, every
    /// decision recorded under the old spelling silently stops matching and
    /// the user is asked all over again.
    #[test]
    fn resource_ids_survive_a_round_trip() {
        let resources = [
            Resource::Camera,
            Resource::Microphone,
            Resource::ScreenCapture,
            Resource::Location,
            Resource::InputCapture,
            Resource::Account(AccountResource::Email),
            Resource::Account(AccountResource::Calendar),
            Resource::Account(AccountResource::Contacts),
            Resource::Account(AccountResource::Chat),
            Resource::Account(AccountResource::Drive),
            Resource::Account(AccountResource::Tasks),
        ];

        for resource in resources {
            let id = resource.as_id();
            assert_eq!(
                Resource::from_id(&id),
                Some(resource.clone()),
                "id {id} did not round-trip"
            );
        }
    }

    #[test]
    fn the_ids_are_the_ones_written_to_disk() {
        assert_eq!(Resource::Camera.as_id(), "camera");
        assert_eq!(Resource::ScreenCapture.as_id(), "screen-capture");
        assert_eq!(
            Resource::Account(AccountResource::Email).as_id(),
            "account.email"
        );
    }

    #[test]
    fn an_unknown_id_is_rejected_rather_than_guessed() {
        assert_eq!(Resource::from_id("nonsense"), None);
        assert_eq!(Resource::from_id("account.nonsense"), None);
        assert_eq!(Resource::from_id("account."), None);
        assert_eq!(Resource::from_id(""), None);
    }
}

#[cfg(test)]
mod delegate_tests {
    use super::*;

    #[test]
    fn only_services_installed_by_the_system_may_ask_for_someone_else() {
        assert!(is_delegate("/usr/bin/vasak-accounts"));

        // A program the user can write must never be able to claim it is
        // asking on another program's behalf — it would name whichever
        // already-approved program it liked.
        assert!(!is_delegate("/home/someone/.local/bin/vasak-accounts"));
        assert!(!is_delegate("/tmp/vasak-accounts"));
        assert!(!is_delegate("vasak-accounts"));
        assert!(!is_delegate("/usr/bin/anything-else"));
    }
}

#[cfg(test)]
mod enforcement_tests {
    use super::*;

    /// The list has to match what the service actually stands behind. If a
    /// resource starts being enforced, this is the one place to change.
    /// La cámara y el micrófono: decidirlos cambia algo aunque la garantía no
    /// sea completa todavía. Confundir las dos preguntas dejó el interruptor
    /// sin poder moverse.
    #[test]
    fn deciding_the_camera_now_has_an_effect() {
        assert!(Resource::Camera.decision_has_effect());
        assert!(Resource::Microphone.decision_has_effect());
        assert!(Resource::Account(AccountResource::Email).decision_has_effect());
    }

    /// Y lo que sigue sin control no: guardar una decisión que no cambia nada
    /// es peor que no aceptarla.
    #[test]
    fn deciding_what_nothing_enforces_still_has_none() {
        assert!(!Resource::ScreenCapture.decision_has_effect());
        assert!(!Resource::Location.decision_has_effect());
        assert!(!Resource::InputCapture.decision_has_effect());
    }

    #[test]
    fn only_online_accounts_are_enforced_today() {
        assert!(Resource::Account(AccountResource::Email).is_enforceable());
        assert!(Resource::Account(AccountResource::Drive).is_enforceable());

        // Handed out by PipeWire and the desktop portal, which do not consult
        // this policy — and the portal cannot say which program is asking.
        assert!(!Resource::Camera.is_enforceable());
        assert!(!Resource::Microphone.is_enforceable());
        assert!(!Resource::ScreenCapture.is_enforceable());
        assert!(!Resource::Location.is_enforceable());
        assert!(!Resource::InputCapture.is_enforceable());
    }
}

#[cfg(test)]
mod policy_tests {
    /// La política de D-Bus tiene que dejar al servicio hablarle al agente.
    ///
    /// Sin esa regla el servicio no puede llamarlo —en el bus del sistema los
    /// method calls se deniegan por omisión— y se cae el flujo entero de
    /// preguntar, en silencio y sin que nada deje de compilar. Fue exactamente
    /// lo que pasó: el diálogo de permisos nunca llegaba a aparecer.
    ///
    /// Se comprueba contra el archivo que se instala, y usando la constante,
    /// para que renombrar la interfaz acá haga fallar la prueba en vez de
    /// romper el sistema en silencio.
    #[test]
    fn the_bus_policy_lets_the_service_reach_the_agent() {
        let policy = include_str!("../../packaging/ar.net.vasak.os.Permissions.conf");
        let rule = format!("<allow send_interface=\"{}\"/>", super::AGENT_INTERFACE);
        assert!(
            policy.contains(&rule),
            "la política instalada no deja al servicio llamar al agente; \
             falta la regla: {rule}"
        );
    }
}
