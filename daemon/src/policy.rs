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
    /// Si este programa consulta al servicio antes de usar el recurso.
    ///
    /// Con `default` para que una política escrita antes de que este campo
    /// existiera se siga leyendo: sale en `false`, que es lo que valía hasta
    /// ahora — todo lo anotado venía de observar un bloqueo.
    #[serde(default)]
    asks: bool,
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
    /// Anota una decisión.
    ///
    /// `pregunto` dice **de dónde vino**: `true` si el programa consultó al
    /// servicio, `false` si lo que se observó fue un bloqueo del kernel. No es
    /// un detalle contable — decide si la pantalla puede ofrecer cambiarla,
    /// porque un programa que pregunta respeta la respuesta aunque ningún
    /// perfil lo limite.
    pub fn record(
        &mut self,
        application: &Application,
        resource_id: &str,
        decision: Decision,
        pregunto: bool,
    ) {
        let entry = self
            .applications
            .entry(application.binary_path.clone())
            .or_insert_with(|| StoredApplication {
                display_name: application.display_name.clone(),
                provenance: application.provenance,
                asks: false,
                decisions: BTreeMap::new(),
            });

        // Refresh the descriptive fields: a program can be renamed, or moved
        // from the user's home into a system path by a later install.
        entry.display_name = application.display_name.clone();
        entry.provenance = application.provenance;
        // Una vez que preguntó, sigue siendo de los que preguntan: que después
        // se le fije la decisión desde la pantalla no lo convierte en otra cosa.
        entry.asks = entry.asks || pregunto;

        entry.decisions.insert(resource_id.to_string(), decision);
    }

    /// Forgets a program entirely, so the next request asks again.
    pub fn forget(&mut self, binary_path: &str) -> bool {
        self.applications.remove(binary_path).is_some()
    }

    /// Lo que la pantalla muestra.
    ///
    /// Se sacan las decisiones que caen fuera del alcance declarado del
    /// programa. No es cosmética: `decide` niega esos recursos sin mirar lo
    /// guardado, así que el interruptor no haría nada en ninguna de sus dos
    /// posiciones — y un interruptor que parece protección sin serlo es peor
    /// que ninguno.
    ///
    /// Pasa con lo que quedó decidido **antes** de que el programa tuviera
    /// alcance: esas decisiones siguen en el archivo, sin efecto. No se borran
    /// acá porque leer no debería escribir; si el alcance se amplía más
    /// adelante, vuelven a valer y vuelven a mostrarse.
    pub fn entries(&self) -> Vec<PermissionEntry> {
        self.applications
            .iter()
            .map(|(binary_path, stored)| {
                let decisions = stored
                    .decisions
                    .iter()
                    .filter(|(resource_id, _)| {
                        vasak_permissions_protocol::may_request(binary_path, resource_id)
                    })
                    .map(|(resource_id, decision)| (resource_id.clone(), *decision))
                    .collect();

                PermissionEntry {
                    application: Application {
                        binary_path: binary_path.clone(),
                        display_name: stored.display_name.clone(),
                        provenance: stored.provenance,
                    },
                    asks: stored.asks,
                    decisions,
                }
            })
            .collect()
    }
}

/// Reads and writes the per-user policy files.
#[derive(Clone)]
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

    /// Una decisión fuera del alcance del programa no se muestra.
    ///
    /// Puede existir en el archivo: quedó de antes de que ese programa tuviera
    /// alcance declarado. Pero `decide` la niega sin mirar lo guardado, así que
    /// el interruptor no haría nada en ninguna de sus dos posiciones — y un
    /// interruptor que parece protección sin serlo es peor que ninguno.
    #[test]
    fn lo_que_esta_fuera_del_alcance_no_llega_a_la_pantalla() {
        let gestor = "/usr/bin/vasak-file-manager";
        let mut politica = UserPolicy::default();

        // Lo que sí puede pedir, y lo que le quedó decidido de antes.
        politica.record(&application(gestor), "account.drive", Decision::Allowed, true);
        politica.record(&application(gestor), "account.email", Decision::Allowed, true);

        let entrada = politica
            .entries()
            .into_iter()
            .find(|e| e.application.binary_path == gestor)
            .expect("la aplicación tiene que seguir figurando");

        assert!(entrada.decisions.contains_key("account.drive"));
        assert!(
            !entrada.decisions.contains_key("account.email"),
            "no puede mostrarse un permiso que decide() niega igual"
        );

        // Y no se borra del archivo: leer no escribe, y si el alcance se
        // amplía más adelante la decisión vuelve a valer.
        assert!(politica.decision(gestor, "account.email").is_allowed());
    }

    /// Un programa que no está en la lista sigue mostrando todo lo suyo: la
    /// lista acota a las aplicaciones propias, no esconde las de terceros.
    #[test]
    fn un_programa_sin_alcance_muestra_todas_sus_decisiones() {
        let ajeno = "/home/alguien/.local/bin/algo";
        let mut politica = UserPolicy::default();
        politica.record(&application(ajeno), "account.email", Decision::Allowed, true);
        politica.record(&application(ajeno), "camera", Decision::Denied, true);

        let entrada = politica.entries().into_iter().next().unwrap();
        assert_eq!(entrada.decisions.len(), 2);
    }

    /// Preguntar y ser bloqueado son dos orígenes distintos, y la pantalla
    /// necesita distinguirlos: un programa del sistema no tiene perfil que lo
    /// limite, así que su interruptor no serviría de nada **salvo** que sea de
    /// los que preguntan — y entonces sí.
    #[test]
    fn se_recuerda_si_el_programa_pregunta() {
        let mut politica = UserPolicy::default();
        politica.record(&application("/usr/bin/vasak-connect"), "camera", Decision::Allowed, true);
        politica.record(&application("/home/x/a.AppImage"), "camera", Decision::Denied, false);

        let entradas = politica.entries();
        let pregunta = |ruta: &str| {
            entradas.iter().find(|e| e.application.binary_path == ruta).unwrap().asks
        };
        assert!(pregunta("/usr/bin/vasak-connect"));
        assert!(!pregunta("/home/x/a.AppImage"));
    }

    /// Y no deja de serlo porque después se le fije la decisión desde la
    /// pantalla. Si se perdiera, el interruptor se apagaría solo justo después
    /// de usarlo, y no habría forma de volver atrás.
    #[test]
    fn fijar_la_decision_a_mano_no_lo_degrada() {
        let mut politica = UserPolicy::default();
        let app = application("/usr/bin/vasak-connect");
        politica.record(&app, "camera", Decision::Allowed, true);
        politica.record(&app, "camera", Decision::Denied, false);

        assert!(politica.entries()[0].asks, "dejó de figurar como que pregunta");
        assert_eq!(politica.decision("/usr/bin/vasak-connect", "camera"), Decision::Denied);
    }

    /// Una política escrita antes de que este campo existiera se sigue
    /// leyendo, y sale como lo que valía hasta ahora: todo venía de observar
    /// un bloqueo.
    #[test]
    fn una_politica_vieja_se_lee_sin_el_campo() {
        let vieja = r#"{"applications":{"/home/x/a.AppImage":{
            "display_name":"a","provenance":"unverified","decisions":{"camera":"denied"}}}}"#;
        let politica: UserPolicy = serde_json::from_str(vieja).expect("se lee");
        assert!(!politica.entries()[0].asks);
        assert_eq!(politica.decision("/home/x/a.AppImage", "camera"), Decision::Denied);
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

        policy.record(&app, "camera", Decision::Allowed, false);
        assert_eq!(policy.decision("/usr/bin/meet", "camera"), Decision::Allowed);

        policy.record(&app, "camera", Decision::Denied, false);
        assert_eq!(policy.decision("/usr/bin/meet", "camera"), Decision::Denied);
        assert_eq!(policy.entries().len(), 1, "still one entry for the program");
    }

    /// Allowing the camera must not answer for the microphone as well.
    #[test]
    fn resources_are_decided_one_at_a_time() {
        let mut policy = UserPolicy::default();
        let app = application("/usr/bin/meet");

        policy.record(&app, "camera", Decision::Allowed, false);

        assert_eq!(policy.decision("/usr/bin/meet", "camera"), Decision::Allowed);
        assert_eq!(
            policy.decision("/usr/bin/meet", "microphone"),
            Decision::Unknown
        );
    }

    #[test]
    fn forgetting_a_program_makes_it_ask_again() {
        let mut policy = UserPolicy::default();
        policy.record(&application("/usr/bin/meet"), "camera", Decision::Denied, false);

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
        policy.record(&application("/usr/bin/meet"), "camera", Decision::Allowed, false);
        policy.record(&application("/usr/bin/meet"), "microphone", Decision::Denied, false);
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
        first.record(&application("/usr/bin/meet"), "camera", Decision::Allowed, false);
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
