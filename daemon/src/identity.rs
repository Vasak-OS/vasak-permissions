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

    if SYSTEM_PREFIXES.iter().any(|prefix| path.starts_with(prefix)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_the_user_can_replace_are_marked_unverified() {
        // Real files, so the existence check is not what decides the outcome.
        assert_eq!(provenance_of(Path::new("/usr/bin/env")), Provenance::SystemInstalled);
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
            matching_entry_name(entry, Path::new("/usr/bin/vasak-resonance"), "vasak-resonance"),
            Some("Reproductor".into())
        );
    }

    #[test]
    fn an_entry_for_another_program_is_not_used() {
        let entry = "[Desktop Entry]\nName=Otra cosa\nExec=/usr/bin/something-else\n";
        assert_eq!(
            matching_entry_name(entry, Path::new("/usr/bin/vasak-resonance"), "vasak-resonance"),
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
            matching_entry_name(entry, Path::new("/usr/bin/vasak-resonance"), "vasak-resonance"),
            Some("Reproductor".into())
        );
    }

    /// Plenty of entries use a bare program name rather than an absolute path.
    #[test]
    fn an_exec_without_a_path_still_matches() {
        let entry = "[Desktop Entry]\nName=Reproductor\nExec=vasak-resonance\n";
        assert_eq!(
            matching_entry_name(entry, Path::new("/usr/bin/vasak-resonance"), "vasak-resonance"),
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
}

/// Describes a program by path alone, for entries the settings screen manages
/// on behalf of a program that is not currently running.
pub fn describe_path(binary_path: &str) -> Application {
    let path = PathBuf::from(binary_path);
    Application {
        binary_path: binary_path.to_string(),
        display_name: display_name_for(&path),
        provenance: provenance_of(&path),
    }
}
