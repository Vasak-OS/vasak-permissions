//! The stored answers, and the file they live in.
//!
//! The file is the reason this service exists. Keeping it in the user's own
//! configuration directory — which is where the online-accounts list used to
//! keep its rules — means any program running as that user can rewrite it and
//! grant itself whatever it likes. Here it belongs to root, one file per user,
//! and the only way to change it is to come through the bus.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vasak_permissions_protocol::{
    Application, BlockedDomain, Decision, PermissionEntry, Provenance,
};

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
    /// Reglas de bloqueo por dominio (M2 del #93): ejecutable → dominios cortados.
    ///
    /// Va aparte de `applications`/`decisions` a propósito: una decisión es sobre
    /// un recurso con nombre (`network`, `camera`), y esto es un conjunto de
    /// dominios por ejecutable, que el cortafuegos resuelve a IPs y corta. Con
    /// `default` y `skip_serializing_if` para que una política escrita antes de
    /// M2 se siga leyendo —sale vacía— y una sin reglas no engorde el archivo.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    domain_rules: BTreeMap<String, BTreeSet<String>>,
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

    /// Los ejecutables con el kill-switch de red **prendido**: decisión `Denied`
    /// sobre `network`. Es lo que el cortafuegos tiene que enrolar para este
    /// usuario —se usa al armar el conjunto de red cortada al arrancar—.
    ///
    /// Sólo `Denied` corta: `Allowed` y `Unknown` dejan pasar (M0 es
    /// default-allow + opt-in). Las claves son rutas de ejecutable; una decisión
    /// de red nunca se guarda contra una identidad del portal, que no tiene pid.
    pub fn binaries_with_network_cut(&self) -> Vec<String> {
        self.applications
            .iter()
            .filter(|(_, app)| app.decisions.get("network") == Some(&Decision::Denied))
            .map(|(binary_path, _)| binary_path.clone())
            .collect()
    }

    /// Prende o apaga una regla de bloqueo por dominio de un ejecutable (M2).
    ///
    /// `blocked = true` agrega el dominio al conjunto del ejecutable; `false` lo
    /// saca, y si era el último el ejecutable sale del mapa (no queda una entrada
    /// vacía). Devuelve si algo cambió —para no reescribir el archivo ni
    /// resincronizar el cortafuegos al pedir lo que ya estaba—.
    ///
    /// `domain` tiene que venir ya normalizado por
    /// [`vasak_permissions_protocol::valid_domain`]: acá no se valida de nuevo, el
    /// servicio lo hace antes de guardar.
    pub fn set_domain_rule(&mut self, binary_path: &str, domain: &str, blocked: bool) -> bool {
        if blocked {
            self.domain_rules
                .entry(binary_path.to_string())
                .or_default()
                .insert(domain.to_string())
        } else {
            let Some(set) = self.domain_rules.get_mut(binary_path) else {
                return false;
            };
            let changed = set.remove(domain);
            if set.is_empty() {
                self.domain_rules.remove(binary_path);
            }
            changed
        }
    }

    /// Todas las reglas de bloqueo por dominio de este usuario, aplanadas, para
    /// `ListDomainRules`. Una fila por `(ejecutable, dominio)`.
    pub fn domain_rules(&self) -> Vec<BlockedDomain> {
        self.domain_rules
            .iter()
            .flat_map(|(binary_path, domains)| {
                domains.iter().map(move |domain| BlockedDomain {
                    binary_path: binary_path.clone(),
                    domain: domain.clone(),
                })
            })
            .collect()
    }

    /// Forgets a program entirely, so the next request asks again.
    pub fn forget(&mut self, binary_path: &str) -> bool {
        self.applications.remove(binary_path).is_some()
    }

    /// Olvida **una sola** decisión de un programa, dejando las demás en pie.
    ///
    /// A diferencia de [`Self::forget`], que borra el programa entero, esto saca
    /// nada más el recurso indicado: es lo que deja que una aplicación vuelva a
    /// pedir **un** permiso suyo —el botón «pedir permiso de nuevo»— sin perder
    /// lo que ya había decidido sobre los otros. El próximo chequeo de ese
    /// recurso queda en `Unknown` y vuelve a abrir el diálogo.
    ///
    /// Si era la última decisión del programa, el programa sale del archivo,
    /// igual que si se lo hubiera olvidado entero: un programa sin ninguna
    /// decisión no es nada que la pantalla tenga que mostrar.
    ///
    /// Devuelve si había algo que olvidar.
    pub fn forget_resource(&mut self, binary_path: &str, resource_id: &str) -> bool {
        let Some(app) = self.applications.get_mut(binary_path) else {
            return false;
        };
        let removed = app.decisions.remove(resource_id).is_some();
        if app.decisions.is_empty() {
            self.applications.remove(binary_path);
        }
        removed
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

/// Ajustes **globales** del servicio: no por usuario, sino del equipo. Van en su
/// propio archivo (`settings.json`), aparte de las políticas por uid.
///
/// Hoy guarda sólo el interruptor del **log de bloqueos del cortafuegos** (M3 del
/// #93). Cada campo con `default` para que un archivo anterior a M3 —o ausente, un
/// sistema recién instalado— se lea sin romper: sale en su valor por omisión.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalSettings {
    /// Si el log persistente de bloqueos del cortafuegos está prendido. **Apagado
    /// por omisión**: un sistema recién instalado no registra nada. Apagarlo detiene
    /// las escrituras; **no** borra lo guardado (borrar es `ClearFirewallLog`).
    #[serde(default)]
    pub firewall_logging_enabled: bool,
}

/// El nombre del archivo de ajustes globales, bajo el directorio de política. Su
/// raíz (`settings`) no parsea como uid, así que los barridos por `<uid>.json`
/// (`red_cortada_inicial`, `domain_rules_initial`) lo saltean.
const SETTINGS_FILE: &str = "settings.json";

/// Reads and writes the per-user policy files.
#[derive(Debug, Clone)]
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
        serde_json::from_str(&raw).map_err(|e| {
            format!(
                "la política de permisos en {} está dañada: {e}",
                path.display()
            )
        })
    }

    /// El conjunto de red cortada de todos los usuarios con política: para cada
    /// archivo `<uid>.json` del directorio, los ejecutables con `network` en
    /// `Denied`. Es lo que el cortafuegos enrola al arrancar, antes de empezar a
    /// confiar en el conector de procesos.
    ///
    /// Un archivo ilegible o dañado se saltea —no se aborta el arranque por la
    /// política de un usuario—: el barrido de `/proc` al reconciliar sólo marca
    /// lo que este conjunto dice, así que un usuario que falte queda sin corte,
    /// no con un corte equivocado.
    pub fn red_cortada_inicial(&self) -> HashMap<u32, HashSet<String>> {
        let mut red = HashMap::new();
        let Ok(entradas) = std::fs::read_dir(&self.directory) else {
            return red;
        };
        for entrada in entradas.flatten() {
            let Some(uid) = entrada
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(policy) = self.load(uid) else {
                continue;
            };
            let cortados = policy.binaries_with_network_cut();
            if !cortados.is_empty() {
                red.insert(uid, cortados.into_iter().collect());
            }
        }
        red
    }

    /// Las reglas de bloqueo por dominio de todos los usuarios con política, por
    /// uid y ejecutable (M2). Es lo que el cortafuegos carga al arrancar para saber
    /// qué pids enrolar y qué dominios resolver, antes de confiar en el conector de
    /// procesos y el snoop de DNS.
    ///
    /// Un archivo ilegible o dañado se saltea, igual que en [`Self::red_cortada_inicial`]:
    /// un usuario que falte queda sin reglas de dominio, no con unas equivocadas.
    pub fn domain_rules_initial(&self) -> HashMap<u32, HashMap<String, HashSet<String>>> {
        let mut reglas = HashMap::new();
        let Ok(entradas) = std::fs::read_dir(&self.directory) else {
            return reglas;
        };
        for entrada in entradas.flatten() {
            let Some(uid) = entrada
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(policy) = self.load(uid) else {
                continue;
            };
            let mut por_binario: HashMap<String, HashSet<String>> = HashMap::new();
            for (binary_path, domains) in &policy.domain_rules {
                if !domains.is_empty() {
                    por_binario.insert(binary_path.clone(), domains.iter().cloned().collect());
                }
            }
            if !por_binario.is_empty() {
                reglas.insert(uid, por_binario);
            }
        }
        reglas
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

    /// El directorio donde viven los archivos del servicio. Lo usa el log de
    /// bloqueos del cortafuegos (M3) para poner los suyos al lado de las políticas,
    /// de root y 0700, y respeta el override de desarrollo
    /// (`VASAK_PERMISSIONS_TEST_ROOT`) sin tener que repetirlo.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn settings_path(&self) -> PathBuf {
        self.directory.join(SETTINGS_FILE)
    }

    /// Lee los ajustes globales. Un archivo ausente —un sistema recién instalado—
    /// son los ajustes por omisión (todo apagado). Uno ilegible o dañado se trata
    /// igual, con un aviso: para un interruptor de log, el valor seguro ante la duda
    /// es **apagado**, no seguir registrando con un archivo que no se entiende.
    pub fn load_settings(&self) -> GlobalSettings {
        let path = self.settings_path();
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return GlobalSettings::default();
        };
        serde_json::from_str(&raw).unwrap_or_else(|e| {
            tracing::warn!(
                "los ajustes globales en {} están dañados ({e}); se usan los \
                 valores por omisión (log de bloqueos apagado)",
                path.display()
            );
            GlobalSettings::default()
        })
    }

    /// Guarda los ajustes globales, de forma atómica y 0600, como las políticas.
    pub fn save_settings(&self, settings: &GlobalSettings) -> Result<(), String> {
        std::fs::create_dir_all(&self.directory)
            .map_err(|e| format!("no se pudo crear {}: {e}", self.directory.display()))?;
        let _ = std::fs::set_permissions(&self.directory, PermissionsExt::from_mode(0o700));

        let serialised = serde_json::to_string_pretty(settings)
            .map_err(|e| format!("no se pudo serializar los ajustes: {e}"))?;
        write_atomically(&self.settings_path(), serialised.as_bytes())
            .map_err(|e| format!("no se pudo guardar los ajustes: {e}"))
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
        politica.record(
            &application(gestor),
            "account.drive",
            Decision::Allowed,
            true,
        );
        politica.record(
            &application(gestor),
            "account.email",
            Decision::Allowed,
            true,
        );

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
        politica.record(
            &application(ajeno),
            "account.email",
            Decision::Allowed,
            true,
        );
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
        politica.record(
            &application("/usr/bin/vasak-connect"),
            "camera",
            Decision::Allowed,
            true,
        );
        politica.record(
            &application("/home/x/a.AppImage"),
            "camera",
            Decision::Denied,
            false,
        );

        let entradas = politica.entries();
        let pregunta = |ruta: &str| {
            entradas
                .iter()
                .find(|e| e.application.binary_path == ruta)
                .unwrap()
                .asks
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

        assert!(
            politica.entries()[0].asks,
            "dejó de figurar como que pregunta"
        );
        assert_eq!(
            politica.decision("/usr/bin/vasak-connect", "camera"),
            Decision::Denied
        );
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
        assert_eq!(
            politica.decision("/home/x/a.AppImage", "camera"),
            Decision::Denied
        );
    }

    /// Sólo los ejecutables con `network` en `Denied` salen como red cortada:
    /// `Allowed` y `Unknown` dejan pasar, y otros recursos no cuentan.
    #[test]
    fn solo_los_de_red_denegada_cuentan_como_cortados() {
        let mut policy = UserPolicy::default();
        policy.record(
            &application("/home/x/a.AppImage"),
            "network",
            Decision::Denied,
            false,
        );
        policy.record(
            &application("/home/x/b.AppImage"),
            "network",
            Decision::Allowed,
            false,
        );
        // Una decisión de otro recurso del mismo binario no lo mete en la lista.
        policy.record(
            &application("/home/x/c.AppImage"),
            "camera",
            Decision::Denied,
            false,
        );
        // Y un binario con red permitida y algo más denegado tampoco.
        policy.record(
            &application("/home/x/b.AppImage"),
            "camera",
            Decision::Denied,
            false,
        );

        let cortados = policy.binaries_with_network_cut();
        assert_eq!(cortados, vec!["/home/x/a.AppImage".to_string()]);
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
        assert_eq!(
            policy.decision("/usr/bin/meet", "camera"),
            Decision::Allowed
        );

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

        assert_eq!(
            policy.decision("/usr/bin/meet", "camera"),
            Decision::Allowed
        );
        assert_eq!(
            policy.decision("/usr/bin/meet", "microphone"),
            Decision::Unknown
        );
    }

    #[test]
    fn forgetting_a_program_makes_it_ask_again() {
        let mut policy = UserPolicy::default();
        policy.record(
            &application("/usr/bin/meet"),
            "camera",
            Decision::Denied,
            false,
        );

        assert!(policy.forget("/usr/bin/meet"));
        assert_eq!(
            policy.decision("/usr/bin/meet", "camera"),
            Decision::Unknown
        );
        assert!(!policy.forget("/usr/bin/meet"), "already gone");
    }

    /// Olvidar un recurso deja los demás en pie: es la diferencia con `forget`,
    /// y es lo que hace que «pedir de nuevo» la cámara no borre lo decidido para
    /// el micrófono.
    #[test]
    fn olvidar_un_recurso_no_toca_los_demas() {
        let mut policy = UserPolicy::default();
        let app = application("/usr/bin/meet");
        policy.record(&app, "camera", Decision::Denied, true);
        policy.record(&app, "microphone", Decision::Allowed, true);

        assert!(policy.forget_resource("/usr/bin/meet", "camera"));
        assert_eq!(
            policy.decision("/usr/bin/meet", "camera"),
            Decision::Unknown,
            "el recurso olvidado vuelve a sin decidir"
        );
        assert_eq!(
            policy.decision("/usr/bin/meet", "microphone"),
            Decision::Allowed,
            "olvidar la cámara no puede borrar el micrófono"
        );
    }

    /// Si era la última decisión, el programa sale del archivo entero, igual que
    /// con `forget`: un programa sin decisiones no es nada que la pantalla
    /// muestre.
    #[test]
    fn olvidar_el_ultimo_recurso_saca_el_programa() {
        let mut policy = UserPolicy::default();
        policy.record(
            &application("/usr/bin/meet"),
            "camera",
            Decision::Denied,
            true,
        );

        assert!(policy.forget_resource("/usr/bin/meet", "camera"));
        assert!(
            policy.entries().is_empty(),
            "sin ninguna decisión no queda entrada del programa"
        );
    }

    /// Olvidar lo que no estaba no inventa nada y no toca lo que sí estaba.
    #[test]
    fn olvidar_lo_que_no_estaba_no_hace_nada() {
        let mut policy = UserPolicy::default();
        policy.record(
            &application("/usr/bin/meet"),
            "camera",
            Decision::Denied,
            true,
        );

        assert!(!policy.forget_resource("/usr/bin/meet", "microphone"));
        assert!(!policy.forget_resource("/usr/bin/otro", "camera"));
        assert_eq!(
            policy.decision("/usr/bin/meet", "camera"),
            Decision::Denied,
            "lo que había sigue intacto"
        );
    }

    #[test]
    fn decisions_survive_being_written_and_read_back() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());

        let mut policy = UserPolicy::default();
        policy.record(
            &application("/usr/bin/meet"),
            "camera",
            Decision::Allowed,
            false,
        );
        policy.record(
            &application("/usr/bin/meet"),
            "microphone",
            Decision::Denied,
            false,
        );
        store.save(1000, &policy).expect("save");

        let reloaded = store.load(1000).expect("load");
        assert_eq!(
            reloaded.decision("/usr/bin/meet", "camera"),
            Decision::Allowed
        );
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
        first.record(
            &application("/usr/bin/meet"),
            "camera",
            Decision::Allowed,
            false,
        );
        store.save(1000, &first).expect("save");

        assert_eq!(
            store
                .load(1001)
                .expect("load")
                .decision("/usr/bin/meet", "camera"),
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

    /// El conjunto inicial reúne la red cortada de cada usuario con política, por
    /// uid, y saltea lo que no es un `<uid>.json`.
    #[test]
    fn el_conjunto_inicial_de_red_cortada_reune_a_cada_usuario() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());

        let mut p1000 = UserPolicy::default();
        p1000.record(
            &application("/home/a/x.AppImage"),
            "network",
            Decision::Denied,
            false,
        );
        p1000.record(
            &application("/home/a/y.AppImage"),
            "network",
            Decision::Allowed,
            false,
        );
        store.save(1000, &p1000).expect("save");

        let mut p1001 = UserPolicy::default();
        p1001.record(
            &application("/home/b/z.AppImage"),
            "network",
            Decision::Denied,
            false,
        );
        store.save(1001, &p1001).expect("save");

        // Un usuario sin red cortada no aparece.
        let mut p1002 = UserPolicy::default();
        p1002.record(
            &application("/home/c/w.AppImage"),
            "camera",
            Decision::Denied,
            false,
        );
        store.save(1002, &p1002).expect("save");

        // Un archivo ajeno al patrón no rompe nada.
        std::fs::write(dir.path().join("notas.txt"), "nada").expect("write");

        let red = store.red_cortada_inicial();
        assert_eq!(red.len(), 2, "sólo 1000 y 1001 tienen red cortada");
        assert_eq!(
            red.get(&1000),
            Some(&HashSet::from(["/home/a/x.AppImage".to_string()]))
        );
        assert_eq!(
            red.get(&1001),
            Some(&HashSet::from(["/home/b/z.AppImage".to_string()]))
        );
    }

    /// Los dominios bloqueados de un ejecutable según `domain_rules`, para las
    /// pruebas.
    fn dominios_de(policy: &UserPolicy, app: &str) -> Vec<String> {
        policy
            .domain_rules()
            .into_iter()
            .filter(|r| r.binary_path == app)
            .map(|r| r.domain)
            .collect()
    }

    /// Prender y apagar una regla de dominio: se agrega, se saca, y al quedar sin
    /// dominios el ejecutable sale del mapa (no deja una entrada vacía).
    #[test]
    fn una_regla_de_dominio_se_prende_y_se_apaga() {
        let mut policy = UserPolicy::default();
        let app = "/usr/bin/vasak-mail";

        assert!(
            policy.set_domain_rule(app, "ads.com", true),
            "nueva regla cambia"
        );
        assert!(
            !policy.set_domain_rule(app, "ads.com", true),
            "pedir la misma regla no cambia nada"
        );
        assert!(policy.set_domain_rule(app, "track.io", true));
        assert_eq!(dominios_de(&policy, app), vec!["ads.com", "track.io"]);

        // No contagia a otro ejecutable.
        assert!(dominios_de(&policy, "/usr/bin/otro").is_empty());

        assert!(
            policy.set_domain_rule(app, "ads.com", false),
            "quitar cambia"
        );
        assert!(
            !policy.set_domain_rule(app, "ads.com", false),
            "quitar lo que no está no cambia nada"
        );
        assert_eq!(dominios_de(&policy, app), vec!["track.io"]);

        // Al sacar el último, el ejecutable sale del mapa.
        assert!(policy.set_domain_rule(app, "track.io", false));
        assert!(dominios_de(&policy, app).is_empty());
        assert!(policy.domain_rules().is_empty());
    }

    /// `domain_rules` aplana todas las reglas en filas `(ejecutable, dominio)`,
    /// ordenadas, para `ListDomainRules`.
    #[test]
    fn las_reglas_de_dominio_se_listan_aplanadas() {
        let mut policy = UserPolicy::default();
        policy.set_domain_rule("/usr/bin/b", "z.com", true);
        policy.set_domain_rule("/usr/bin/a", "y.com", true);
        policy.set_domain_rule("/usr/bin/a", "x.com", true);

        let reglas = policy.domain_rules();
        let filas: Vec<(String, String)> = reglas
            .into_iter()
            .map(|r| (r.binary_path, r.domain))
            .collect();
        assert_eq!(
            filas,
            vec![
                ("/usr/bin/a".into(), "x.com".into()),
                ("/usr/bin/a".into(), "y.com".into()),
                ("/usr/bin/b".into(), "z.com".into()),
            ]
        );
    }

    /// Las reglas de dominio sobreviven el guardado y la relectura, y una política
    /// anterior a M2 (sin el campo) se sigue leyendo sin reglas.
    #[test]
    fn las_reglas_de_dominio_se_guardan_y_se_releen() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());

        let mut policy = UserPolicy::default();
        policy.set_domain_rule("/usr/bin/vasak-mail", "ads.com", true);
        store.save(1000, &policy).expect("save");

        let reloaded = store.load(1000).expect("load");
        assert_eq!(
            dominios_de(&reloaded, "/usr/bin/vasak-mail"),
            vec!["ads.com"]
        );

        // Una política vieja, sin `domain_rules`, se lee sin reglas.
        let vieja = r#"{"applications":{}}"#;
        let p: UserPolicy = serde_json::from_str(vieja).expect("se lee");
        assert!(p.domain_rules().is_empty());
    }

    /// El conjunto inicial de reglas de dominio reúne a cada usuario con política,
    /// por uid y ejecutable, y saltea lo que no es un `<uid>.json`.
    #[test]
    fn el_conjunto_inicial_de_reglas_de_dominio_reune_a_cada_usuario() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());

        let mut p1000 = UserPolicy::default();
        p1000.set_domain_rule("/usr/bin/vasak-mail", "ads.com", true);
        p1000.set_domain_rule("/usr/bin/vasak-mail", "track.io", true);
        store.save(1000, &p1000).expect("save");

        // Un usuario sin reglas de dominio no aparece.
        let mut p1001 = UserPolicy::default();
        p1001.record(
            &application("/home/b/z.AppImage"),
            "camera",
            Decision::Denied,
            false,
        );
        store.save(1001, &p1001).expect("save");

        std::fs::write(dir.path().join("notas.txt"), "nada").expect("write");

        let reglas = store.domain_rules_initial();
        assert_eq!(reglas.len(), 1, "sólo 1000 tiene reglas de dominio");
        assert_eq!(
            reglas.get(&1000).and_then(|m| m.get("/usr/bin/vasak-mail")),
            Some(&HashSet::from([
                "ads.com".to_string(),
                "track.io".to_string()
            ]))
        );
    }

    #[test]
    fn a_missing_file_is_simply_an_empty_policy() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());
        assert!(store.load(4242).expect("load").entries().is_empty());
    }

    /// Apagado por omisión: sin archivo de ajustes —un sistema recién instalado— el
    /// log de bloqueos está apagado.
    #[test]
    fn el_log_de_bloqueos_viene_apagado_por_omision() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());
        assert!(
            !store.load_settings().firewall_logging_enabled,
            "un sistema recién instalado no registra nada"
        );
    }

    /// El interruptor del log sobrevive el guardado y la relectura, y el archivo de
    /// ajustes es 0600 (no legible por el mundo) y no se confunde con una política
    /// por uid.
    #[test]
    fn el_interruptor_del_log_se_guarda_y_se_relee() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PolicyStore::at(dir.path().to_path_buf());

        store
            .save_settings(&GlobalSettings {
                firewall_logging_enabled: true,
            })
            .expect("save");
        assert!(
            store.load_settings().firewall_logging_enabled,
            "quedó prendido"
        );

        let mode = std::fs::metadata(dir.path().join(SETTINGS_FILE))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "los ajustes no pueden ser legibles por el mundo"
        );

        // El archivo de ajustes no se cuenta como la red cortada de un usuario.
        assert!(
            store.red_cortada_inicial().is_empty(),
            "settings.json no es un <uid>.json"
        );
    }

    /// Un archivo de ajustes dañado no se trata como «prendido»: ante la duda, el
    /// log queda apagado (el valor seguro para un interruptor de log).
    #[test]
    fn un_archivo_de_ajustes_danado_cae_a_apagado() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join(SETTINGS_FILE), "{ roto").expect("write");
        let store = PolicyStore::at(dir.path().to_path_buf());
        assert!(!store.load_settings().firewall_logging_enabled);
    }

    /// Un archivo de ajustes anterior a este campo (un `{}`) se lee sin romper y sale
    /// apagado: el `default` del campo lo cubre.
    #[test]
    fn un_archivo_de_ajustes_anterior_a_m3_se_lee_apagado() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join(SETTINGS_FILE), "{}").expect("write");
        let store = PolicyStore::at(dir.path().to_path_buf());
        assert!(!store.load_settings().firewall_logging_enabled);
    }

    /// Lo decidido por el portal se guarda, se lee y llega a la pantalla.
    ///
    /// Es el recorrido entero del cambio, del lado del almacén: la clave del
    /// portal no es una ruta, y el archivo, el filtro de alcance y la lista que
    /// lee Configuración tienen que tratarla igual que a cualquier otra. Si
    /// `entries()` la dejara afuera, la decisión se guardaría y no habría forma
    /// de retirarla — que es media mitad del problema que esto viene a
    /// arreglar.
    #[test]
    fn lo_decidido_por_el_portal_llega_a_la_pantalla() {
        let key =
            vasak_permissions_protocol::portal_key("com.google.Chrome").expect("identidad válida");
        let app = Application {
            binary_path: key.clone(),
            display_name: "com.google.Chrome".into(),
            provenance: Provenance::Unverified,
        };

        let mut politica = UserPolicy::default();
        politica.record(&app, "screen-capture", Decision::Allowed, true);
        politica.record(&app, "camera", Decision::Denied, true);

        assert!(politica.decision(&key, "screen-capture").is_allowed());
        assert!(!politica.decision(&key, "camera").is_allowed());

        let entrada = politica
            .entries()
            .into_iter()
            .find(|e| e.application.binary_path == key)
            .expect("la identidad del portal tiene que figurar");

        assert_eq!(
            entrada.decisions.get("screen-capture"),
            Some(&Decision::Allowed)
        );
        assert_eq!(entrada.decisions.get("camera"), Some(&Decision::Denied));
        // `asks` en verdadero: el portal pregunta antes de entregar el recurso y
        // respeta la respuesta. Sin esto la pantalla mostraría el interruptor
        // apagado, por no encontrar un perfil que lo sostenga.
        assert!(entrada.asks);
    }

    /// Y se puede olvidar, que es lo que deja volver a preguntar.
    #[test]
    fn una_identidad_del_portal_se_puede_olvidar() {
        let key =
            vasak_permissions_protocol::portal_key("com.google.Chrome").expect("identidad válida");
        let mut politica = UserPolicy::default();
        politica.record(
            &Application {
                binary_path: key.clone(),
                display_name: "com.google.Chrome".into(),
                provenance: Provenance::Unverified,
            },
            "screen-capture",
            Decision::Allowed,
            true,
        );

        assert!(politica.forget(&key));
        assert_eq!(politica.decision(&key, "screen-capture"), Decision::Unknown);
    }
}
