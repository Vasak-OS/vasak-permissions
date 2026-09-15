//! Working out which program is asking.
//!
//! A permission is only worth anything if the answer to "who is calling" cannot
//! be faked. Two things matter here: pinning the process before reading
//! anything about it, and being honest about how much the resulting path is
//! worth.

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use vasak_permissions_protocol::{Application, Provenance};

/// Paths only root can write to.
///
/// A decision recorded against a binary in one of these cannot be turned into
/// a decision about *different* code without root — which is exactly the
/// property that makes remembering an answer safe.
const SYSTEM_PREFIXES: [&str; 3] = ["/usr/", "/opt/", "/bin/"];

/// Si un delegado puede preguntar por un proceso de este usuario.
///
/// ── El bug que esto arregla ─────────────────────────────────────────────────
///
/// La regla era `subject.uid == delegate.uid` a secas, y con eso **ninguna
/// aplicación pudo usar jamás una cuenta en línea**: el calendario, el correo,
/// los contactos y el gestor de archivos recibían
///
///     org.freedesktop.DBus.Error.AccessDenied:
///     el proceso indicado pertenece a otro usuario
///
/// sin que se mostrara un solo diálogo, porque la negativa llega antes de
/// preguntarle a nadie.
///
/// El único delegado de la lista es `/usr/bin/vasak-accounts`, y corre como
/// root a propósito: los tokens viven en archivos de root, que es justamente lo
/// que impide que un programa del usuario los lea por su cuenta. O sea que el
/// delegado siempre tiene uid 0 y el sujeto siempre es un proceso del usuario:
/// la igualdad no podía darse nunca.
///
/// No se vio antes porque en desarrollo los dos corren con el mismo usuario
/// —ahí la comparación es verdadera— y porque esta regla no tenía ninguna
/// prueba. Se rompe sólo instalado, que es donde nadie la estaba mirando.
///
/// ── Qué se conserva ─────────────────────────────────────────────────────────
///
/// Lo que la regla quería evitar sigue evitado, y por dos caminos. El de fondo
/// es que `decide` carga y guarda la política con el uid del **sujeto**, así
/// que la respuesta de una persona nunca se escribe en la carpeta de otra,
/// venga de donde venga la pregunta.
///
/// Y queda el cerco para un delegado sin privilegios: alguien puede correr una
/// copia de `/usr/bin/vasak-accounts` como su propio usuario —pasa
/// `is_delegate`, que mira la ruta del binario y no quién lo ejecuta— y desde
/// ahí preguntar por procesos ajenos. Eso filtraría la decisión de otra persona
/// en el valor de retorno, y le abriría diálogos en su sesión. Un delegado no
/// privilegiado sigue confinado a su propio usuario.
pub fn delegate_may_speak_for(delegate_uid: u32, subject_uid: u32) -> bool {
    delegate_uid == 0 || delegate_uid == subject_uid
}

/// A caller whose PID has been pinned open.
///
/// While the `pidfd` is held the kernel cannot reuse that PID for another
/// process, so reading `/proc/<pid>/exe` afterwards is not a race: the path
/// belongs to the process that actually made the call, and not to whatever
/// started up in its place a microsecond later.
pub struct PinnedCaller {
    pub pid: u32,
    pub uid: u32,
    pub executable: PathBuf,
    _pidfd: OwnedFd,
}

impl PinnedCaller {
    /// Pins a process somebody else named, checking it is still the same one.
    ///
    /// A delegate hands over a PID it saw a moment ago. By the time this runs
    /// that process could have exited and its number been given to something
    /// else — so the start time is compared as well, which is the pair the
    /// kernel guarantees to be unique. Without it, a delegate could be tricked
    /// into naming a process that no longer exists and the answer would be
    /// recorded against whatever inherited the number.
    pub fn capture_subject(pid: u32, start_time: u64) -> Result<Self, String> {
        let uid = std::fs::metadata(format!("/proc/{pid}"))
            .map(|meta| std::os::unix::fs::MetadataExt::uid(&meta))
            .map_err(|e| format!("el proceso {pid} ya no existe: {e}"))?;

        let pinned = Self::capture(pid, uid)?;

        let actual = crate::polkit::start_time_of(pid)?;
        if actual != start_time {
            return Err(format!(
                "el proceso {pid} no es el que se indicó: el número fue reutilizado"
            ));
        }

        Ok(pinned)
    }

    pub fn capture(pid: u32, uid: u32) -> Result<Self, String> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if raw < 0 {
            return Err(format!(
                "no se pudo fijar el proceso {pid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: a descriptor just returned by a successful pidfd_open.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as std::os::fd::RawFd) };

        let executable = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|e| format!("no se pudo resolver el ejecutable del proceso {pid}: {e}"))?;

        Ok(Self {
            pid,
            uid,
            // Resolve symlinks so the same program cannot be recorded twice
            // under two different names.
            executable: std::fs::canonicalize(&executable).unwrap_or(executable),
            _pidfd: pidfd,
        })
    }

    pub fn binary_path(&self) -> String {
        self.executable.to_string_lossy().into_owned()
    }

    /// Describes the caller for the policy and for the dialog.
    pub fn describe(&self) -> Application {
        Application {
            binary_path: self.binary_path(),
            display_name: display_name_for(&self.executable),
            provenance: provenance_of(&self.executable),
        }
    }
}

/// Whether the executable lives somewhere the user could replace it.
///
/// A program under the user's home is still allowed to ask, and the answer is
/// still remembered — but the dialog says the program is unverified, because
/// nothing stops its contents from being swapped afterwards. This is the same
/// distinction macOS draws with an unidentified developer.
fn provenance_of(executable: &Path) -> Provenance {
    let path = executable.to_string_lossy();

    // A deleted binary's link reads as "/usr/bin/foo (deleted)"; treat anything
    // that is not a plain existing file as unverified.
    if !executable.is_file() {
        return Provenance::Unverified;
    }

    if SYSTEM_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        Provenance::SystemInstalled
    } else {
        Provenance::Unverified
    }
}

/// A name a person will recognise.
///
/// Taken from the desktop entry when one matches, because "Cámara" is
/// meaningful and "vasak-camera-tool" is not. Falls back to the file name.
fn display_name_for(executable: &Path) -> String {
    let file_name = executable
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| executable.to_string_lossy().into_owned());

    desktop_entry_name(executable).unwrap_or(file_name)
}

fn desktop_entry_name(executable: &Path) -> Option<String> {
    let file_name = executable.file_name()?.to_string_lossy().into_owned();

    for directory in ["/usr/share/applications", "/usr/local/share/applications"] {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "desktop") {
                continue;
            }
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };

            if let Some(name) = matching_entry_name(&contents, executable, &file_name) {
                return Some(name);
            }
        }
    }

    None
}

/// Reads a desktop entry and returns its `Name` when its `Exec` runs this
/// program. Only the `[Desktop Entry]` group is considered, so a name from an
/// action group ("New Window") cannot win over the real one.
fn matching_entry_name(contents: &str, executable: &Path, file_name: &str) -> Option<String> {
    let mut in_entry_group = false;
    let mut name = None;
    let mut matches = false;

    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry_group = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry_group {
            continue;
        }

        // Localised keys (`Name[es]`) are skipped: the service has no user
        // locale, and picking one arbitrarily would be worse than the default.
        if let Some(value) = line.strip_prefix("Name=") {
            name = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Exec=") {
            let program = value.split_whitespace().next().unwrap_or("");
            matches = program == executable.to_string_lossy() || program == file_name;
        }
    }

    matches.then_some(name).flatten()
}

/// Describes a program by path alone, for entries the settings screen manages
/// on behalf of a program that is not currently running.
///
/// Atiende también las identidades del portal, que no son rutas. Hacerlo acá y
/// no en cada llamador es lo que impide que una de ellas termine tratada como
/// un archivo: `display_name_for` le sacaría el «nombre de archivo» a
/// `portal:com.google.Chrome` y `provenance_of` diría que no existe en el disco
/// —que es cierto y no significa nada—, y la pantalla mostraría las dos cosas
/// como si fueran un programa que no encontró.
pub fn describe_path(binary_path: &str) -> Application {
    if let Some(app_id) = vasak_permissions_protocol::portal_app_id(binary_path) {
        return Application {
            binary_path: binary_path.to_string(),
            // El `app_id` tal cual. Resolverlo contra los `.desktop` para
            // sacarle un nombre lindo es trabajo de la pantalla, que ya lo hace
            // para los iconos y que puede equivocarse sin consecuencias; acá
            // una resolución fallida dejaría la entrada sin nombre.
            display_name: app_id.to_string(),
            // No verificada, y es la parte importante de esta rama. Este nombre
            // lo declaró la aplicación llamando al registro del portal y no lo
            // comprobó nadie, así que decir cualquier otra cosa sería afirmar
            // algo que no se sabe.
            provenance: Provenance::Unverified,
        };
    }

    let path = PathBuf::from(binary_path);
    Application {
        binary_path: binary_path.to_string(),
        display_name: display_name_for(&path),
        provenance: provenance_of(&path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El delegado de sistema tiene que poder hablar por el usuario.
    ///
    /// Es el caso real y el que estaba roto: `/usr/bin/vasak-accounts` corre
    /// como root —los tokens viven en archivos de root— y pregunta por el
    /// calendario, el correo o los contactos, que corren como la persona. Con
    /// la regla vieja, `uid 0 != uid 1000` y **ninguna aplicación pudo usar
    /// nunca una cuenta en línea**: `AccessDenied` antes de mostrar un solo
    /// diálogo.
    #[test]
    fn el_delegado_de_sistema_habla_por_cualquier_usuario() {
        assert!(delegate_may_speak_for(0, 1000));
        assert!(delegate_may_speak_for(0, 1001));
        assert!(delegate_may_speak_for(0, 0));
    }

    /// Y el que no es de sistema sigue confinado a su propio usuario.
    ///
    /// `is_delegate` mira la ruta del binario, no quién lo ejecuta, así que
    /// alguien puede correr una copia como su propio usuario. Desde ahí,
    /// preguntar por un proceso ajeno filtraría la decisión de otra persona en
    /// el valor de retorno y le abriría diálogos en su sesión.
    #[test]
    fn un_delegado_sin_privilegios_no_puede_preguntar_por_otro_usuario() {
        assert!(delegate_may_speak_for(1000, 1000), "su propio usuario, sí");
        assert!(!delegate_may_speak_for(1000, 1001), "el de al lado, no");
        assert!(!delegate_may_speak_for(1000, 0), "y root menos todavía");
    }

    /// The pairing of PID and start time is what makes a delegated request
    /// safe. A delegate hands over a number it saw a moment ago; if only the
    /// number were checked, a process that exited and had its number reused
    /// would be silently mistaken for the original.
    #[test]
    fn a_delegated_subject_must_match_its_start_time() {
        let pid = std::process::id();
        let start_time = crate::polkit::start_time_of(pid).expect("start time");

        let pinned = PinnedCaller::capture_subject(pid, start_time).expect("correct start time");
        assert_eq!(pinned.pid, pid);

        assert!(
            PinnedCaller::capture_subject(pid, start_time + 1).is_err(),
            "a mismatched start time means the number was reused"
        );
    }

    #[test]
    fn a_process_that_no_longer_exists_cannot_be_pinned() {
        assert!(PinnedCaller::capture_subject(999_999_999, 0).is_err());
    }

    #[test]
    fn programs_the_user_can_replace_are_marked_unverified() {
        // Real files, so the existence check is not what decides the outcome.
        assert_eq!(
            provenance_of(Path::new("/usr/bin/env")),
            Provenance::SystemInstalled
        );
        assert_eq!(
            provenance_of(Path::new("/home/someone/.local/bin/tool")),
            Provenance::Unverified
        );
    }

    /// A binary that no longer exists cannot be vouched for, whatever its path
    /// says — `/proc/<pid>/exe` still points at a path after the file behind it
    /// is replaced or deleted.
    #[test]
    fn a_missing_binary_is_never_treated_as_system_installed() {
        assert_eq!(
            provenance_of(Path::new("/usr/bin/definitely-not-installed-xyz")),
            Provenance::Unverified
        );
    }

    #[test]
    fn a_desktop_entry_gives_the_program_its_real_name() {
        let entry = "[Desktop Entry]\nName=Reproductor\nExec=/usr/bin/vasak-resonance %U\n";
        assert_eq!(
            matching_entry_name(
                entry,
                Path::new("/usr/bin/vasak-resonance"),
                "vasak-resonance"
            ),
            Some("Reproductor".into())
        );
    }

    #[test]
    fn an_entry_for_another_program_is_not_used() {
        let entry = "[Desktop Entry]\nName=Otra cosa\nExec=/usr/bin/something-else\n";
        assert_eq!(
            matching_entry_name(
                entry,
                Path::new("/usr/bin/vasak-resonance"),
                "vasak-resonance"
            ),
            None
        );
    }

    /// Names in action groups belong to menu items, not to the program.
    #[test]
    fn only_the_main_group_provides_the_name() {
        let entry = "[Desktop Entry]\n\
                     Name=Reproductor\n\
                     Exec=/usr/bin/vasak-resonance\n\
                     \n\
                     [Desktop Action New]\n\
                     Name=Ventana nueva\n";
        assert_eq!(
            matching_entry_name(
                entry,
                Path::new("/usr/bin/vasak-resonance"),
                "vasak-resonance"
            ),
            Some("Reproductor".into())
        );
    }

    /// Plenty of entries use a bare program name rather than an absolute path.
    #[test]
    fn an_exec_without_a_path_still_matches() {
        let entry = "[Desktop Entry]\nName=Reproductor\nExec=vasak-resonance\n";
        assert_eq!(
            matching_entry_name(
                entry,
                Path::new("/usr/bin/vasak-resonance"),
                "vasak-resonance"
            ),
            Some("Reproductor".into())
        );
    }

    #[test]
    fn a_program_without_a_desktop_entry_falls_back_to_its_file_name() {
        assert_eq!(
            display_name_for(Path::new("/usr/bin/definitely-not-installed-xyz")),
            "definitely-not-installed-xyz"
        );
    }

    /// Una identidad del portal se describe como lo que es.
    ///
    /// Sin la rama que la atiende, `display_name_for` le sacaría el «nombre de
    /// archivo» a `portal:com.google.Chrome` —o sea, la cadena entera— y
    /// `provenance_of` diría «no verificada» por la razón equivocada: porque no
    /// existe ese archivo en el disco. Da la misma respuesta por casualidad, y
    /// una casualidad no es algo sobre lo que apoyar una pantalla de seguridad.
    #[test]
    fn una_identidad_del_portal_se_describe_como_tal() {
        let key = vasak_permissions_protocol::portal_key("com.google.Chrome")
            .expect("identidad válida");
        let app = describe_path(&key);

        assert_eq!(app.binary_path, "portal:com.google.Chrome");
        assert_eq!(app.display_name, "com.google.Chrome");
        assert_eq!(app.provenance, Provenance::Unverified);
    }

    /// Y nunca verificada, que es lo que esta rama tiene que sostener.
    ///
    /// El `app_id` lo declara la propia aplicación y no lo comprueba nadie.
    /// Marcarlo como instalado por el sistema —aunque el nombre sea el de un
    /// programa que sí lo está— afirmaría algo que no se sabe.
    #[test]
    fn ninguna_identidad_del_portal_queda_verificada() {
        for app_id in ["com.google.Chrome", "ar.net.vasak.os.Settings", "cualquiera"] {
            let key =
                vasak_permissions_protocol::portal_key(app_id).expect("identidad válida");
            assert_eq!(describe_path(&key).provenance, Provenance::Unverified, "{app_id}");
        }
    }
}
