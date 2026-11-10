//! El **log persistente de bloqueos** del cortafuegos (M3 del #93): opt-in,
//! apagado por omisión, y registra **sólo** las conexiones que el cortafuegos
//! cortó —nunca una permitida—.
//!
//! # Qué separa este módulo
//!
//! Lo testeable sin tocar privilegios vive en las funciones puras —la
//! [`clasificar`]ción del motivo, [`armar_entrada`], el [`formatear`]do del
//! registro, [`parsear_log`] y la decisión de [`debe_rotar`]— y se prueba con el
//! patrón cores+mock. La **escritura real al archivo** ([`RegistroCortafuegos`])
//! es el adapter de I/O; lo demás no lo toca.
//!
//! # Apagar ≠ borrar
//!
//! El interruptor ([`FirewallLog::set_enabled`]) sólo detiene las escrituras: lo
//! ya guardado queda. Borrar es [`FirewallLog::borrar`], una acción aparte y
//! explícita (detrás de polkit en el servicio).
//!
//! # Privacidad
//!
//! El archivo dice quién se conectó a dónde: se crea **de root y 0600** (no
//! legible por el mundo), en el directorio de política (0700). `ReadFirewallLog`
//! filtra por el uid del llamante, así que un usuario sólo ve sus propios
//! bloqueos.
//!
//! # Acotado
//!
//! El activo tiene un tope de tamaño; al pasarlo rota (el activo pasa a `.1`,
//! descartando el `.1` anterior —lo más viejo se cae—), así que el total nunca
//! supera dos veces el tope. Nunca crece sin límite.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use vasak_permissions_protocol::FirewallLogEntry;

/// El tope del archivo activo, en bytes. Al pasarlo, rota; con un `.1` del mismo
/// tamaño, el total queda acotado en el doble. Una línea ronda los ~150 bytes, así
/// que 1 MiB son unos miles de bloqueos por archivo: holgado sin ser ilimitado.
const MAX_BYTES: u64 = 1024 * 1024;

/// El nombre del archivo activo del log, bajo el directorio de política. Su raíz
/// (`firewall-blocks`) no parsea como uid, así que los barridos por `<uid>.json`
/// (`red_cortada_inicial`, `domain_rules_initial`) lo saltean.
const ARCHIVO: &str = "firewall-blocks.log";
/// El rotado: el activo anterior, lo más viejo que todavía se conserva.
const ARCHIVO_ROTADO: &str = "firewall-blocks.log.1";

/// El motivo best-effort de un corte, derivado en userspace del estado de política
/// que el daemon ya mantiene. **No** sale del programa BPF (que no emite el
/// motivo): es una aproximación, por eso existe [`Motivo::Desconocido`] para cuando
/// no se puede clasificar limpio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motivo {
    /// La red de la app está cortada entera (kill-switch de M0).
    KillSwitch,
    /// La IP de destino cae bajo una regla de dominio de la app (M2).
    ReglaDominio,
    /// Resolvedor del sistema forzado: 53/853/443 a un destino no permitido (M2,
    /// PR-C). Se infiere de que la app tiene reglas de dominio y el puerto es uno
    /// de esos.
    ResolvedorForzado,
    /// No se pudo clasificar: el corte se registra igual, sin motivo preciso.
    Desconocido,
}

impl Motivo {
    /// El token estable que va al registro. Vacío para [`Motivo::Desconocido`]: un
    /// bloqueo sin motivo preciso se guarda igual, con el campo en blanco.
    pub fn as_str(self) -> &'static str {
        match self {
            Motivo::KillSwitch => "kill-switch",
            Motivo::ReglaDominio => "domain-rule",
            Motivo::ResolvedorForzado => "forced-resolver",
            Motivo::Desconocido => "",
        }
    }
}

/// Clasifica el motivo del corte, de lo más cierto a lo menos. Función pura:
///
/// - `cortado`: la red de la app está cortada entera → `kill-switch` (gana sobre
///   todo: si está, todo lo suyo se corta por eso).
/// - `ip_por_dominio`: el dominio que la app resolvió para esta IP está entre los
///   que bloquea → `domain-rule`.
/// - `tiene_reglas_dominio` con puerto 53/853/443 → `forced-resolver` (la app está
///   bajo forzado del resolvedor; el corte en esos puertos sale de ahí).
/// - si nada de eso → `Desconocido` (best-effort, se documenta).
pub fn clasificar(
    cortado: bool,
    ip_por_dominio: bool,
    tiene_reglas_dominio: bool,
    puerto: u16,
) -> Motivo {
    if cortado {
        Motivo::KillSwitch
    } else if ip_por_dominio {
        Motivo::ReglaDominio
    } else if tiene_reglas_dominio && matches!(puerto, 53 | 853 | 443) {
        Motivo::ResolvedorForzado
    } else {
        Motivo::Desconocido
    }
}

/// Arma la línea del log a partir de los datos crudos del evento y el motivo ya
/// clasificado. El destino es el dominio que la app resolvió, si lo hay, o la IP
/// cruda. Función pura.
#[allow(clippy::too_many_arguments)]
pub fn armar_entrada(
    timestamp_secs: u64,
    uid: u32,
    binary_path: &str,
    ip: &str,
    domain: Option<&str>,
    port: u16,
    proto: &str,
    motivo: Motivo,
) -> FirewallLogEntry {
    FirewallLogEntry {
        timestamp_secs,
        uid,
        binary_path: binary_path.to_string(),
        destination: domain.unwrap_or(ip).to_string(),
        port,
        proto: proto.to_string(),
        reason: motivo.as_str().to_string(),
    }
}

/// Serializa una entrada como **una** línea JSON (JSON Lines): fácil de agregar al
/// final y de filtrar por uid al leer. `to_string` no mete saltos, así que la
/// línea es una sola; se le agrega el `\n`.
pub fn formatear(entrada: &FirewallLogEntry) -> String {
    let mut linea = serde_json::to_string(entrada).unwrap_or_default();
    linea.push('\n');
    linea
}

/// Parsea el contenido del log (una entrada JSON por línea) y devuelve **sólo** las
/// de `uid`: es el filtro por uid del llamante de `ReadFirewallLog`. Una línea que
/// no parsea se saltea —un archivo a medio escribir o una línea vieja no tumba la
/// lectura—. Función pura.
pub fn parsear_log(contenido: &str, uid: u32) -> Vec<FirewallLogEntry> {
    contenido
        .lines()
        .filter_map(|linea| serde_json::from_str::<FirewallLogEntry>(linea).ok())
        .filter(|entrada| entrada.uid == uid)
        .collect()
}

/// Si el archivo activo tiene que rotar **antes** de escribir `linea_len` bytes: si
/// ya tiene algo y pasaría el tope con la línea nueva. Un activo vacío nunca rota
/// (una línea sola más grande que el tope entra igual, al activo nuevo; no se
/// pierde). Función pura.
pub fn debe_rotar(tam_actual: u64, linea_len: usize, max_bytes: u64) -> bool {
    tam_actual > 0 && tam_actual.saturating_add(linea_len as u64) > max_bytes
}

/// El adapter de I/O: dónde viven los dos archivos y su tope. Agrega, lee y borra
/// tocando el disco. La lógica pura (rotar, parsear) vive arriba; acá sólo la E/S.
pub struct RegistroCortafuegos {
    activo: PathBuf,
    rotado: PathBuf,
    max_bytes: u64,
}

impl RegistroCortafuegos {
    fn nuevo(dir: &Path, max_bytes: u64) -> Self {
        Self {
            activo: dir.join(ARCHIVO),
            rotado: dir.join(ARCHIVO_ROTADO),
            max_bytes,
        }
    }

    /// Agrega una línea al activo, rotando antes si hiciera falta. Crea el archivo
    /// **0600** (de root, no legible por el mundo) y el directorio **0700**, como la
    /// política.
    fn agregar(&self, linea: &str) -> std::io::Result<()> {
        if let Some(dir) = self.activo.parent() {
            std::fs::create_dir_all(dir)?;
            // 0700: el listado del directorio ya dice qué uids tienen política.
            let _ = std::fs::set_permissions(dir, PermissionsExt::from_mode(0o700));
        }
        let tam = std::fs::metadata(&self.activo)
            .map(|m| m.len())
            .unwrap_or(0);
        if debe_rotar(tam, linea.len(), self.max_bytes) {
            // El `.1` anterior se descarta con el rename: lo más viejo se cae.
            std::fs::rename(&self.activo, &self.rotado)?;
        }
        let mut archivo = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            // Creado 0600 de entrada, no arreglado después: el contenido nunca
            // queda legible por otro usuario ni un instante.
            .mode(0o600)
            .open(&self.activo)?;
        archivo.write_all(linea.as_bytes())
    }

    /// Lee los dos archivos (el rotado primero, lo más viejo) y devuelve las
    /// entradas de `uid`. La lectura es I/O; el filtro y el parseo son puros.
    fn leer(&self, uid: u32) -> Vec<FirewallLogEntry> {
        let mut contenido = String::new();
        for ruta in [&self.rotado, &self.activo] {
            if let Ok(texto) = std::fs::read_to_string(ruta) {
                contenido.push_str(&texto);
            }
        }
        parsear_log(&contenido, uid)
    }

    /// Borra los dos archivos. Que uno no exista no es error (apagar no borra, así
    /// que el rotado puede no estar). Es `ClearFirewallLog`.
    fn borrar(&self) -> std::io::Result<()> {
        for ruta in [&self.activo, &self.rotado] {
            match std::fs::remove_file(ruta) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// El log compartido entre el lector del ring buffer (que agrega) y el servicio
/// (que prende/apaga, lee y borra). El interruptor es un `AtomicBool` —se consulta
/// por cada evento bloqueado, barato y sin candado—; el I/O va tras un `Mutex` que
/// serializa agregar/leer/borrar entre sí. El candado es de `std` y nunca se
/// sostiene a través de un `.await`.
pub struct FirewallLog {
    enabled: AtomicBool,
    io: Mutex<RegistroCortafuegos>,
}

/// Lo que se comparte: el daemon lo clona (`Arc`) al lector y al servicio.
pub type FirewallLogCompartido = Arc<FirewallLog>;

/// Arma el log para el directorio de política, con el interruptor en `enabled` (lo
/// que `load_settings` leyó: **apagado** en un sistema recién instalado).
pub fn nuevo(dir: &Path, enabled: bool) -> FirewallLogCompartido {
    Arc::new(FirewallLog {
        enabled: AtomicBool::new(enabled),
        io: Mutex::new(RegistroCortafuegos::nuevo(dir, MAX_BYTES)),
    })
}

impl FirewallLog {
    /// Si el log está prendido. El lector lo consulta antes de hacer el trabajo de
    /// clasificar el motivo, para no pagarlo cuando está apagado.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Prende o apaga las escrituras. **No** borra: lo guardado queda.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Agrega una entrada **si el log está prendido**. Best-effort: un fallo de I/O
    /// se registra y se sigue —el log no puede romper el camino del ring—.
    pub fn registrar(&self, entrada: &FirewallLogEntry) {
        if !self.enabled() {
            return;
        }
        let linea = formatear(entrada);
        let Ok(reg) = self.io.lock() else {
            return;
        };
        if let Err(e) = reg.agregar(&linea) {
            tracing::warn!("No se pudo escribir el log de bloqueos del cortafuegos: {e}");
        }
    }

    /// Las entradas de `uid`, filtradas como pide `ReadFirewallLog`.
    pub fn leer(&self, uid: u32) -> Vec<FirewallLogEntry> {
        self.io.lock().map(|r| r.leer(uid)).unwrap_or_default()
    }

    /// Borra el log entero (`ClearFirewallLog`). Error legible si el candado está
    /// envenenado o la E/S falla.
    pub fn borrar(&self) -> Result<(), String> {
        self.io
            .lock()
            .map_err(|_| "el candado del log de bloqueos está envenenado".to_string())?
            .borrar()
            .map_err(|e| format!("no se pudo borrar el log de bloqueos: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entrada_ejemplo(uid: u32, reason: &str) -> FirewallLogEntry {
        FirewallLogEntry {
            timestamp_secs: 1_788_000_000,
            uid,
            binary_path: "/home/x/app".into(),
            destination: "192.0.2.1".into(),
            port: 443,
            proto: "tcp".into(),
            reason: reason.into(),
        }
    }

    // ── La clasificación del motivo ───────────────────────────────────────────

    /// El kill-switch gana sobre todo: si la red de la app está cortada, el motivo
    /// es `kill-switch` aunque también tenga reglas de dominio y la IP case.
    #[test]
    fn el_kill_switch_gana_sobre_el_resto() {
        assert_eq!(clasificar(true, true, true, 443), Motivo::KillSwitch);
        assert_eq!(clasificar(true, false, false, 80), Motivo::KillSwitch);
    }

    /// Sin kill-switch, una IP que cae bajo una regla de dominio es `domain-rule`.
    #[test]
    fn la_ip_bajo_regla_de_dominio_es_domain_rule() {
        assert_eq!(clasificar(false, true, true, 443), Motivo::ReglaDominio);
        // Aunque el puerto no sea de resolvedor: la regla manda.
        assert_eq!(clasificar(false, true, true, 8080), Motivo::ReglaDominio);
    }

    /// Sin kill-switch ni IP de dominio, pero con reglas y puerto de resolvedor, es
    /// `forced-resolver`: el corte de 53/853/443 sale del forzado.
    #[test]
    fn un_puerto_de_resolvedor_con_reglas_es_forced_resolver() {
        for puerto in [53u16, 853, 443] {
            assert_eq!(
                clasificar(false, false, true, puerto),
                Motivo::ResolvedorForzado
            );
        }
    }

    /// Lo que no encaja en ninguna categoría queda `Desconocido` (motivo en blanco):
    /// un puerto de resolvedor sin reglas, o un puerto cualquiera, no se inventan un
    /// motivo.
    #[test]
    fn lo_que_no_encaja_queda_desconocido() {
        // Puerto de resolvedor pero sin reglas de dominio: no se puede atribuir.
        assert_eq!(clasificar(false, false, false, 53), Motivo::Desconocido);
        // Con reglas pero puerto que no es de resolvedor ni casó la IP.
        assert_eq!(clasificar(false, false, true, 80), Motivo::Desconocido);
        assert_eq!(Motivo::Desconocido.as_str(), "");
    }

    /// Los tokens del motivo son los estables que el servicio y la pantalla esperan.
    #[test]
    fn los_tokens_del_motivo_son_estables() {
        assert_eq!(Motivo::KillSwitch.as_str(), "kill-switch");
        assert_eq!(Motivo::ReglaDominio.as_str(), "domain-rule");
        assert_eq!(Motivo::ResolvedorForzado.as_str(), "forced-resolver");
    }

    // ── Armado y formato del registro ─────────────────────────────────────────

    /// El destino es el dominio si lo hay; si no, la IP cruda. El resto de los
    /// campos salen tal cual del evento.
    #[test]
    fn el_destino_usa_el_dominio_o_cae_a_la_ip() {
        let con_dominio = armar_entrada(
            10,
            1000,
            "/home/x/app",
            "93.184.216.34",
            Some("example.com"),
            443,
            "tcp",
            Motivo::ReglaDominio,
        );
        assert_eq!(con_dominio.destination, "example.com");
        assert_eq!(con_dominio.reason, "domain-rule");
        assert_eq!(con_dominio.timestamp_secs, 10);
        assert_eq!(con_dominio.uid, 1000);
        assert_eq!(con_dominio.port, 443);
        assert_eq!(con_dominio.proto, "tcp");

        let sin_dominio = armar_entrada(
            10,
            1000,
            "/home/x/app",
            "93.184.216.34",
            None,
            443,
            "tcp",
            Motivo::KillSwitch,
        );
        assert_eq!(
            sin_dominio.destination, "93.184.216.34",
            "sin dominio se muestra la IP"
        );
    }

    /// `formatear` da una sola línea JSON terminada en `\n`, y `parsear_log` la
    /// lee de vuelta: la ida y la vuelta no pierden nada.
    #[test]
    fn formatear_y_parsear_dan_la_vuelta() {
        let entrada = entrada_ejemplo(1000, "kill-switch");
        let linea = formatear(&entrada);
        assert!(linea.ends_with('\n'), "la línea termina en salto");
        assert_eq!(
            linea.matches('\n').count(),
            1,
            "una sola línea por registro"
        );

        let leidas = parsear_log(&linea, 1000);
        assert_eq!(leidas, vec![entrada]);
    }

    // ── Filtro por uid y robustez del parseo ──────────────────────────────────

    /// `parsear_log` devuelve **sólo** las entradas del uid pedido: un usuario no ve
    /// los bloqueos de otro.
    #[test]
    fn parsear_log_filtra_por_uid() {
        let contenido = format!(
            "{}{}{}",
            formatear(&entrada_ejemplo(1000, "kill-switch")),
            formatear(&entrada_ejemplo(1001, "domain-rule")),
            formatear(&entrada_ejemplo(1000, "forced-resolver")),
        );
        let del_1000 = parsear_log(&contenido, 1000);
        assert_eq!(del_1000.len(), 2, "sólo las dos del uid 1000");
        assert!(del_1000.iter().all(|e| e.uid == 1000));
        assert_eq!(parsear_log(&contenido, 1001).len(), 1);
        assert!(parsear_log(&contenido, 4242).is_empty(), "un uid sin nada");
    }

    /// Una línea en blanco o rota se saltea: un archivo a medio escribir no tumba
    /// la lectura ni inventa entradas.
    #[test]
    fn parsear_log_saltea_lineas_rotas() {
        let contenido = format!(
            "no es json\n\n{}basura {{",
            formatear(&entrada_ejemplo(1000, "kill-switch")),
        );
        let leidas = parsear_log(&contenido, 1000);
        assert_eq!(leidas.len(), 1, "sólo la línea válida");
    }

    // ── La decisión de rotar ──────────────────────────────────────────────────

    /// Un activo vacío nunca rota; al pasar el tope con la línea nueva, sí; justo en
    /// el tope, todavía no.
    #[test]
    fn debe_rotar_respeta_el_tope_y_no_rota_vacio() {
        assert!(
            !debe_rotar(0, 1000, 100),
            "vacío no rota ni con línea grande"
        );
        assert!(!debe_rotar(100, 0, 100), "justo en el tope no rota");
        assert!(debe_rotar(100, 1, 100), "pasarlo por un byte rota");
        assert!(debe_rotar(90, 20, 100));
    }

    // ── El adapter contra archivos de verdad (en un tempdir, sin root) ─────────

    /// Un log prendido escribe los bloqueos, los relee filtrados por uid, y apagarlo
    /// detiene las escrituras **sin** borrar lo ya guardado.
    #[test]
    fn prendido_escribe_apagado_no_escribe_pero_no_borra() {
        let dir = tempfile::tempdir().expect("temp dir");
        let log = nuevo(dir.path(), true);

        log.registrar(&entrada_ejemplo(1000, "kill-switch"));
        log.registrar(&entrada_ejemplo(1001, "domain-rule"));
        assert_eq!(log.leer(1000).len(), 1, "se guardó el del 1000");
        assert_eq!(log.leer(1001).len(), 1);

        // Apagar: una escritura más no entra, pero lo guardado sigue.
        log.set_enabled(false);
        log.registrar(&entrada_ejemplo(1000, "forced-resolver"));
        assert_eq!(
            log.leer(1000).len(),
            1,
            "apagado no escribe, y apagar no borra lo anterior"
        );

        // El archivo es 0600 (no legible por el mundo).
        let modo = std::fs::metadata(dir.path().join(ARCHIVO))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(modo, 0o600, "el log no puede ser legible por el mundo");
    }

    /// Un log apagado de entrada (un sistema recién instalado) no registra nada.
    #[test]
    fn apagado_por_omision_no_registra() {
        let dir = tempfile::tempdir().expect("temp dir");
        let log = nuevo(dir.path(), false);
        log.registrar(&entrada_ejemplo(1000, "kill-switch"));
        assert!(log.leer(1000).is_empty(), "apagado no registra");
        assert!(
            !dir.path().join(ARCHIVO).exists(),
            "ni siquiera crea el archivo"
        );
    }

    /// Al pasar el tope, el activo rota y las entradas viejas sobreviven en el `.1`:
    /// la lectura las sigue viendo y el total queda acotado (no crece sin fin).
    #[test]
    fn rota_al_pasar_el_tope_y_conserva_lo_rotado() {
        let dir = tempfile::tempdir().expect("temp dir");
        // Tope diminuto para forzar la rotación en pocas líneas.
        let log = Arc::new(FirewallLog {
            enabled: AtomicBool::new(true),
            io: Mutex::new(RegistroCortafuegos::nuevo(dir.path(), 200)),
        });

        for _ in 0..20 {
            log.registrar(&entrada_ejemplo(1000, "kill-switch"));
        }
        // Rotó al menos una vez: el `.1` existe.
        assert!(
            dir.path().join(ARCHIVO_ROTADO).exists(),
            "tenía que haber rotado"
        );
        // Lo rotado se sigue leyendo, y el activo no supera el doble del tope.
        assert!(
            !log.leer(1000).is_empty(),
            "las entradas sobreviven la rotación"
        );
        let tam_activo = std::fs::metadata(dir.path().join(ARCHIVO))
            .expect("stat")
            .len();
        assert!(tam_activo <= 200 + 200, "el activo queda acotado");
    }

    /// Borrar saca los dos archivos; borrar de nuevo (ya vacío) no es error. Apagar
    /// no borró; esto sí.
    #[test]
    fn borrar_saca_el_log_entero() {
        let dir = tempfile::tempdir().expect("temp dir");
        let log = nuevo(dir.path(), true);
        log.registrar(&entrada_ejemplo(1000, "kill-switch"));
        assert!(!log.leer(1000).is_empty());

        log.borrar().expect("borra");
        assert!(log.leer(1000).is_empty(), "el log quedó vacío");
        assert!(!dir.path().join(ARCHIVO).exists());
        // Borrar lo que ya no está no es error.
        log.borrar().expect("borrar de nuevo no falla");
    }
}
