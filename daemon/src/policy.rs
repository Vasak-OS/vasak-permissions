//! The stored answers, and the file they live in.
//!
//! The file is the reason this service exists. Keeping it in the user's own
//! configuration directory — which is where the online-accounts list used to
//! keep its rules — means any program running as that user can rewrite it and
//! grant itself whatever it likes. Here it belongs to root, one file per user,
//! and the only way to change it is to come through the bus.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vasak_permissions_protocol::{Application, Decision, PermissionEntry, Provenance};

/// Root-owned, outside every user's reach.
const POLICY_DIR: &str = "/var/lib/vasak-permissions";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredApplication {
    display_name: String,
    provenance: Provenance,
    /// Resource id → decision.
    decisions: BTreeMap<String, Decision>,
}

/// Everything decided for one user, keyed by the program's executable path.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UserPolicy {
    #[serde(default)]
    applications: BTreeMap<String, StoredApplication>,
}

impl UserPolicy {
    pub fn decision(&self, binary_path: &str, resource_id: &str) -> Decision {
        self.applications
            .get(binary_path)
            .and_then(|app| app.decisions.get(resource_id))
            .copied()
            .unwrap_or(Decision::Unknown)
    }

    /// Records an answer, replacing whatever was decided before for the same
    /// program and resource.
    pub fn record(&mut self, application: &Application, resource_id: &str, decision: Decision) {
        let entry = self
            .applications
            .entry(application.binary_path.clone())
            .or_insert_with(|| StoredApplication {
                display_name: application.display_name.clone(),
                provenance: application.provenance,
                decisions: BTreeMap::new(),
            });

        // Refresh the descriptive fields: a program can be renamed, or moved
        // from the user's home into a system path by a later install.
        entry.display_name = application.display_name.clone();
        entry.provenance = application.provenance;

        entry.decisions.insert(resource_id.to_string(), decision);
    }

    /// Forgets a program entirely, so the next request asks again.
    pub fn forget(&mut self, binary_path: &str) -> bool {
        self.applications.remove(binary_path).is_some()
    }

    pub fn entries(&self) -> Vec<PermissionEntry> {
        self.applications
            .iter()
            .map(|(binary_path, stored)| PermissionEntry {
                application: Application {
                    binary_path: binary_path.clone(),
                    display_name: stored.display_name.clone(),
                    provenance: stored.provenance,
                },
                decisions: stored.decisions.clone(),
            })
            .collect()
    }
}

/// Reads and writes the per-user policy files.
pub struct PolicyStore {
    directory: PathBuf,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self::at(PathBuf::from(POLICY_DIR))
    }

    /// Development override, compiled only into debug builds.
    ///
    /// The released binary contains no way to move the policy elsewhere, so a
    /// stray environment variable can never point the real service at a
    /// directory somebody else can write.
    #[cfg(debug_assertions)]
    pub fn from_environment() -> Self {
        match std::env::var_os("VASAK_PERMISSIONS_TEST_ROOT") {
            Some(root) => Self::at(PathBuf::from(root)),
            None => Self::new(),
        }
    }

    #[cfg(not(debug_assertions))]
    pub fn from_environment() -> Self {
        Self::new()
    }

    pub fn at(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn path_for(&self, uid: u32) -> PathBuf {
        self.directory.join(format!("{uid}.json"))
    }

    pub fn load(&self, uid: u32) -> Result<UserPolicy, String> {
        let path = self.path_for(uid);
        if !path.exists() {
            return Ok(UserPolicy::default());
        }

        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("no se pudo leer {}: {e}", path.display()))?;

        // A corrupt file must not be treated as "everything is allowed", and
        // must not be silently replaced either — refusing loudly keeps the
        // decisions recoverable by hand.
        serde_json::from_str(&raw)
            .map_err(|e| format!("la política de permisos en {} está dañada: {e}", path.display()))
    }

    pub fn save(&self, uid: u32, policy: &UserPolicy) -> Result<(), String> {
        std::fs::create_dir_all(&self.directory)
            .map_err(|e| format!("no se pudo crear {}: {e}", self.directory.display()))?;
        // 0700: the directory listing itself says which users have policies.
        let _ = std::fs::set_permissions(&self.directory, PermissionsExt::from_mode(0o700));

        let serialised = serde_json::to_string_pretty(policy)
            .map_err(|e| format!("no se pudo serializar la política: {e}"))?;

        write_atomically(&self.path_for(uid), serialised.as_bytes())
            .map_err(|e| format!("no se pudo guardar la política: {e}"))
    }
}

/// Replaces the file in one step so an interrupted write cannot leave a
/// truncated policy behind — a half-written file would fail to parse, and the
/// service would refuse to answer for that user until someone fixed it by hand.
fn write_atomically(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let temp = path.with_extension("tmp");

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        // Created 0600 from the start rather than fixed up afterwards, so the
        // contents are never briefly readable by anyone else.
        .mode(0o600)
        .open(&temp)?;

    let written = file.write_all(data).and_then(|_| file.sync_all());
    drop(file);

    let result = written.and_then(|_| std::fs::rename(&temp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application(path: &str) -> Application {
        Application {
            binary_path: path.to_string(),
            display_name: "Test".into(),
            provenance: Provenance::SystemInstalled,
        }
    }

    #[test]
    fn a_program_nobody_decided_on_is_unknown_not_denied() {
        let policy = UserPolicy::default();
        assert_eq!(
            policy.decision("/usr/bin/anything", "camera"),
            Decision::Unknown,
            "unknown is what makes the service ask; denied would silently refuse forever"
        );
    }

    #[test]
    fn an_answer_replaces_the_previous_one() {
        let mut policy = UserPolicy::default();
        let app = application("/usr/bin/meet");

        policy.record(&app, "camera", Decision::Allowed);
        assert_eq!(policy.decision("/usr/bin/meet", "camera"), Decision::Allowed);

        policy.record(&app, "camera", Decision::Denied);
        assert_eq!(policy.decision("/usr/bin/meet", "camera"), Decision::Denied);
        assert_eq!(policy.entries().len(), 1, "still one entry for the program");
    }

    /// Allowing the camera must not answer for the microphone as well.
    #[test]
    fn resources_are_decided_one_at_a_time() {
        let mut policy = UserPolicy::default();
        let app = application("/usr/bin/meet");

        policy.record(&app, "camera", Decision::Allowed);

        assert_eq!(policy.decision("/usr/bin/meet", "camera"), Decision::Allowed);
        assert_eq!(
            policy.decision("/usr/bin/meet", "microphone"),
            Decision::Unknown
        );
    }

    #[test]
    fn forgetting_a_program_makes_it_ask_again() {
        let mut policy = UserPolicy::default();
        policy.record(&application("/usr/bin/meet"), "camera", Decision::Denied);

        assert!(policy.forget("/usr/bin/meet"));
        assert_eq!(
            policy.decision("/usr/bin/meet", "camera"),
            Decision::Unknown
        );
        assert!(!policy.forget("/usr/bin/meet"), "already gone");
    }

    #[test]
    fn decisions_survive_being_written_and_read_back() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());

        let mut policy = UserPolicy::default();
        policy.record(&application("/usr/bin/meet"), "camera", Decision::Allowed);
        policy.record(&application("/usr/bin/meet"), "microphone", Decision::Denied);
        store.save(1000, &policy).expect("save");

        let reloaded = store.load(1000).expect("load");
        assert_eq!(reloaded.decision("/usr/bin/meet", "camera"), Decision::Allowed);
        assert_eq!(
            reloaded.decision("/usr/bin/meet", "microphone"),
            Decision::Denied
        );
    }

    #[test]
    fn the_policy_file_is_readable_only_by_its_owner() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());
        store.save(1000, &UserPolicy::default()).expect("save");

        let mode = std::fs::metadata(dir.path().join("1000.json"))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the policy must not be world-readable");

        assert!(
            !dir.path().join("1000.tmp").exists(),
            "no temporary file should be left behind"
        );
    }

    #[test]
    fn users_do_not_share_a_policy() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());

        let mut first = UserPolicy::default();
        first.record(&application("/usr/bin/meet"), "camera", Decision::Allowed);
        store.save(1000, &first).expect("save");

        assert_eq!(
            store.load(1001).expect("load").decision("/usr/bin/meet", "camera"),
            Decision::Unknown,
            "another user must not inherit the decision"
        );
    }

    /// Refusing to parse is the safe failure: reading a damaged file as an
    /// empty policy would re-ask for everything, and treating it as allowed
    /// would be worse.
    #[test]
    fn a_damaged_policy_file_is_reported_not_ignored() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("1000.json"), "{ not json").expect("write");

        let store = PolicyStore::at(dir.path().to_path_buf());
        assert!(store.load(1000).is_err());
    }

    #[test]
    fn a_missing_file_is_simply_an_empty_policy() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());
        assert!(store.load(4242).expect("load").entries().is_empty());
    }
}
