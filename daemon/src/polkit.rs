//! Asking polkit whether the person may change the stored permissions.
//!
//! Changing a permission has to be harder than being granted one, or the whole
//! service falls over: a program that was just refused the microphone could
//! simply call `SetPermission` and grant itself the microphone. polkit puts
//! that behind an authentication the user performs, in a dialog the calling
//! program has no control over.

use zbus::fdo::Error as FdoError;
use zbus::zvariant::Value;
use std::collections::HashMap;

use vasak_permissions_protocol::MANAGE_ACTION;

/// Checks the caller against `ar.net.vasak.os.permissions.manage`.
///
/// The subject is identified by `unix-process` with its start time, not by PID
/// alone: a PID can be reused, and polkit needs to be sure it is authenticating
/// the process that actually asked.
pub async fn authorize(
    connection: &zbus::Connection,
    caller: &crate::identity::PinnedCaller,
) -> Result<(), FdoError> {
    let start_time = process_start_time(caller.pid)?;

    let mut subject_details: HashMap<&str, Value<'_>> = HashMap::new();
    subject_details.insert("pid", Value::U32(caller.pid));
    subject_details.insert("start-time", Value::U64(start_time));

    let subject = ("unix-process", subject_details);
    let details: HashMap<&str, &str> = HashMap::new();
    // 1 = allow the interactive authentication dialog. Without it polkit
    // answers "not authorized" for anything needing a password, and the
    // settings screen would just fail with no way for the user to proceed.
    let flags: u32 = 1;
    let cancellation_id = "";

    let reply = connection
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(subject, MANAGE_ACTION, details, flags, cancellation_id),
        )
        .await
        .map_err(|e| FdoError::Failed(format!("no se pudo consultar a polkit: {e}")))?;

    // (is_authorized, is_challenge, details)
    let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) = reply
        .body()
        .deserialize()
        .map_err(|e| FdoError::Failed(format!("respuesta inválida de polkit: {e}")))?;

    if authorized {
        Ok(())
    } else {
        Err(FdoError::AccessDenied(
            "No se autorizó el cambio de permisos".into(),
        ))
    }
}

/// Reads field 22 of `/proc/<pid>/stat`, the process start time in clock ticks.
///
/// Parsed from the last `)` onwards because field 2 is the executable name in
/// parentheses and may itself contain spaces or brackets — splitting the whole
/// line on whitespace misplaces every field after it.
fn process_start_time(pid: u32) -> Result<u64, FdoError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| FdoError::Failed(format!("no se pudo leer /proc/{pid}/stat: {e}")))?;

    parse_start_time(&stat)
        .ok_or_else(|| FdoError::Failed(format!("no se pudo interpretar /proc/{pid}/stat")))
}

fn parse_start_time(stat: &str) -> Option<u64> {
    let after_name = stat.rsplit_once(')')?.1;
    // After the closing bracket the fields are 3 onwards, so the start time
    // (field 22) is the 20th value here.
    after_name.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_start_time_is_read_from_the_right_field() {
        // Fields 1..=22 with the start time (22) set to 4242.
        let mut stat = String::from("1234 (bash) S");
        for field in 4..=21 {
            stat.push_str(&format!(" {field}"));
        }
        stat.push_str(" 4242 rest of the line");

        assert_eq!(parse_start_time(&stat), Some(4242));
    }

    /// A program can be called `foo bar) baz`, and splitting the whole line on
    /// spaces would then read the wrong field — and authenticate the wrong
    /// process.
    #[test]
    fn a_program_name_with_spaces_and_brackets_does_not_shift_the_fields() {
        let mut stat = String::from("1234 (weird ) name) S");
        for field in 4..=21 {
            stat.push_str(&format!(" {field}"));
        }
        stat.push_str(" 99 more");

        assert_eq!(parse_start_time(&stat), Some(99));
    }

    #[test]
    fn a_truncated_stat_line_is_rejected_rather_than_guessed() {
        assert_eq!(parse_start_time("1234 (bash) S 3 4"), None);
        assert_eq!(parse_start_time("nonsense"), None);
        assert_eq!(parse_start_time(""), None);
    }
}
