//! Avisar cuando AppArmor bloquea algo, leyendo el registro del kernel.
//!
//! # Por qué existe
//!
//! Los perfiles de AppArmor que trae VasakOS niegan la cámara y el micrófono a
//! las aplicaciones no verificadas, y lo hacen bien: el kernel corta el acceso
//! sin que la aplicación pueda evitarlo. El problema es que corta **en
//! silencio**. Desde afuera se ve una cámara que no anda, y nadie —ni el
//! usuario ni quien escribió la aplicación— tiene forma de saber por qué.
//!
//! Un bloqueo que no se explica es casi tan malo como no tenerlo: la persona
//! culpa al hardware, o a la aplicación, y termina desinstalando lo que no
//! estaba roto.
//!
//! Esto no agrega ni quita bloqueos. Sólo los cuenta.
//!
//! # De dónde salen los datos
//!
//! El kernel escribe cada denegación en su registro, con esta forma:
//!
//! ```text
//! audit: type=1400 audit(1788539628.817:36077): apparmor="DENIED"
//!   operation="open" class="file" profile="vasak-appimage" name="/dev/video0"
//!   pid=167490 comm="prueba-vasak.Ap" requested_mask="r" denied_mask="r"
//!   fsuid=1000 ouid=0
//! ```
//!
//! Se lee de `/dev/kmsg`, que en este sistema sólo puede leer root
//! (`kernel.dmesg_restrict=1`) — y este servicio ya corre como root, que es
//! justamente por lo que le toca a él y no al agente.
//!
//! El `comm` viene recortado a quince caracteres por el kernel, así que no
//! sirve para identificar la aplicación. Para eso está el `pid`, con el que se
//! resuelve la ruta real del binario: la misma identidad contra la que este
//! servicio guarda sus decisiones.

use vasak_permissions_protocol::Resource;

/// Una denegación de AppArmor, ya interpretada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denegacion {
    /// El perfil que la produjo. Sirve para ignorar las que no son nuestras.
    pub perfil: String,
    /// La ruta a la que se quiso acceder.
    pub ruta: String,
    /// Quién lo intentó. Con esto se resuelve el binario de verdad.
    pub pid: u32,
    /// A qué usuario avisarle.
    pub uid: u32,
}

/// Los perfiles cuyos bloqueos avisamos.
///
/// Sólo los nuestros: el paquete `apparmor` trae 145 perfiles de terceros, y
/// avisar de los suyos sería ruido sobre decisiones que no tomamos nosotros.
const NUESTROS_PERFILES: &[&str] = &["vasak-appimage"];

/// Saca el valor de `clave="valor"` de una línea del registro.
fn texto_de<'l>(linea: &'l str, clave: &str) -> Option<&'l str> {
    let aguja = format!("{clave}=\"");
    let inicio = linea.find(&aguja)? + aguja.len();
    let resto = &linea[inicio..];
    let fin = resto.find('"')?;
    Some(&resto[..fin])
}

/// Saca el valor de `clave=123`, que va sin comillas.
fn numero_de(linea: &str, clave: &str) -> Option<u32> {
    // El espacio de adelante evita que `uid=` encuentre el `fsuid=` o el
    // `ouid=` de la misma línea, que están todos juntos y terminan igual.
    let aguja = format!(" {clave}=");
    let inicio = linea.find(&aguja)? + aguja.len();
    let resto = &linea[inicio..];
    let fin = resto.find(|c: char| !c.is_ascii_digit()).unwrap_or(resto.len());
    resto[..fin].parse().ok()
}

/// Interpreta una línea del registro del kernel.
///
/// Devuelve `None` para todo lo que no sea una denegación de uno de nuestros
/// perfiles, que es la enorme mayoría de lo que pasa por ahí.
pub fn parsear(linea: &str) -> Option<Denegacion> {
    if texto_de(linea, "apparmor")? != "DENIED" {
        return None;
    }
    let perfil = texto_de(linea, "profile")?;
    if !NUESTROS_PERFILES.contains(&perfil) {
        return None;
    }
    Some(Denegacion {
        perfil: perfil.to_string(),
        ruta: texto_de(linea, "name")?.to_string(),
        pid: numero_de(linea, "pid")?,
        // `fsuid` y no `ouid`: el primero es quién intentó, el segundo de quién
        // es el archivo. Para saber a quién avisarle hace falta el primero.
        uid: numero_de(linea, "fsuid")?,
    })
}

/// Qué recurso es la ruta que se bloqueó.
///
/// Las rutas son las mismas que niegan los perfiles; si allá se agrega una,
/// acá hay que reconocerla o el bloqueo va a seguir siendo mudo.
pub fn recurso_de(ruta: &str) -> Option<Resource> {
    if ruta.starts_with("/dev/video") {
        return Some(Resource::Camera);
    }
    // En ALSA los dispositivos de captura terminan en `c` y los de
    // reproducción en `p`. El perfil sólo niega los de captura, así que un
    // `pcmC0D0p` acá sería un error de otro lado.
    if ruta.starts_with("/dev/snd/pcm") && ruta.ends_with('c') {
        return Some(Resource::Microphone);
    }
    None
}

// ── El vigilante ────────────────────────────────────────────────────────────

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::time::{Duration, Instant};

/// Cuánto se calla un aviso repetido de la misma aplicación y el mismo recurso.
///
/// Una aplicación a la que se le niega la cámara suele reintentar en bucle: sin
/// esto, un solo intento fallido se convierte en una lluvia de notificaciones.
const SILENCIO: Duration = Duration::from_secs(300);

/// Cuántos avisos pueden estar en vuelo a la vez.
const AVISOS_A_LA_VEZ: usize = 4;

fn cupo() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static CUPO: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    CUPO.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(AVISOS_A_LA_VEZ)))
}

/// Sigue el registro del kernel y avisa de lo que nuestros perfiles bloquean.
///
/// Nunca termina; se lanza como tarea de fondo. Si `/dev/kmsg` no se puede
/// leer, se registra y se sale: un sistema sin AppArmor activo no tiene nada
/// que vigilar, y no es un error.
pub async fn vigilar(connection: zbus::Connection, agents: crate::agent::SharedAgents) {
    let (envio, mut recepcion) = tokio::sync::mpsc::channel::<Denegacion>(64);

    // La lectura de /dev/kmsg bloquea a la espera del próximo mensaje, así que
    // vive en un hilo aparte y manda por el canal lo que reconoce.
    std::thread::spawn(move || {
        let archivo = match std::fs::File::open("/dev/kmsg") {
            Ok(archivo) => archivo,
            Err(error) => {
                tracing::info!(
                    "No se puede leer /dev/kmsg ({error}); \
                     no se avisará de lo que AppArmor bloquee"
                );
                return;
            }
        };
        let mut archivo = archivo;
        // Al final: interesa lo que pase de ahora en más, no el historial del
        // arranque —que además provocaría una andanada de avisos viejos al
        // iniciar sesión—.
        if let Err(error) = archivo.seek(SeekFrom::End(0)) {
            tracing::warn!("No se pudo saltar al final de /dev/kmsg: {error}");
            return;
        }
        for linea in BufReader::new(archivo).lines() {
            let Ok(linea) = linea else { continue };
            if let Some(denegacion) = parsear(&linea) {
                if envio.blocking_send(denegacion).is_err() {
                    return; // el servicio se está cerrando
                }
            }
        }
    });

    let mut recientes: HashMap<(u32, String, String), Instant> = HashMap::new();
    while let Some(denegacion) = recepcion.recv().await {
        let Some(recurso) = recurso_de(&denegacion.ruta) else {
            // Un perfil nuestro negó algo que este módulo no sabe nombrar.
            // Vale la pena que quede escrito: significa que el perfil y esto se
            // desincronizaron.
            tracing::warn!(
                "El perfil '{}' bloqueó '{}', que no sé a qué recurso corresponde",
                denegacion.perfil,
                denegacion.ruta
            );
            continue;
        };

        let Ok(proceso) = crate::identity::PinnedCaller::capture(denegacion.pid, denegacion.uid)
        else {
            // El proceso ya no está. Pasa: puede haberse cerrado justo por no
            // conseguir lo que pedía. Sin él no hay forma de decir *qué*
            // aplicación fue, y un aviso que no nombra a nadie asusta sin
            // informar.
            tracing::info!(
                "Se bloqueó '{}' al proceso {}, que ya no existe; no se avisa",
                denegacion.ruta,
                denegacion.pid
            );
            continue;
        };
        let aplicacion = proceso.describe();

        // El uid va en la clave: si dos personas con sesión abierta usan la
        // misma aplicación, callar a una no puede callar a la otra.
        let clave = (denegacion.uid, aplicacion.binary_path.clone(), recurso.as_id());
        let ahora = Instant::now();
        if let Some(anterior) = recientes.get(&clave) {
            let desde = ahora.duration_since(*anterior);
            if desde < SILENCIO {
                // Se deja constancia. Sin esta línea, un aviso callado por el
                // silencio y un aviso que falló se ven exactamente igual desde
                // el diario —nada—, y averiguar cuál de los dos fue cuesta más
                // que escribirla.
                tracing::debug!(
                    "Callado: ya se avisó de '{}' para {} hace {}s",
                    recurso.as_id(),
                    aplicacion.binary_path,
                    desde.as_secs()
                );
                continue;
            }
        }
        recientes.insert(clave, ahora);
        // Que el mapa no crezca sin techo en una sesión larga.
        recientes.retain(|_, cuando| ahora.duration_since(*cuando) < SILENCIO);

        tracing::info!(
            "AppArmor le negó '{}' a {}; avisando al usuario {}",
            recurso.as_id(),
            aplicacion.binary_path,
            denegacion.uid
        );
        // Aparte, y no `await` acá. Este bucle es el único que vacía el canal
        // que alimenta el hilo lector de /dev/kmsg: si se queda esperando a un
        // agente lento, el canal se llena, el lector se bloquea al enviar y el
        // kernel sigue rotando su registro. Se perderían denegaciones por
        // esperar a una notificación.
        //
        // El cupo evita que un aluvión de aplicaciones distintas —que el
        // silencio de arriba no cubre, porque son claves distintas— abra tareas
        // sin techo.
        let permiso = match cupo().clone().try_acquire_owned() {
            Ok(permiso) => permiso,
            Err(_) => {
                tracing::debug!("Demasiados avisos a la vez; se descarta uno");
                continue;
            }
        };
        let connection = connection.clone();
        let agents = agents.clone();
        let uid = denegacion.uid;
        tokio::spawn(async move {
            let _permiso = permiso;
            crate::agent::avisar_de_bloqueo(&connection, &agents, uid, &aplicacion, &recurso).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Una línea tal cual la escribe el kernel, copiada del registro real.
    const REAL: &str = concat!(
        "audit: type=1400 audit(1788539628.817:36077): apparmor=\"DENIED\" ",
        "operation=\"open\" class=\"file\" profile=\"vasak-appimage\" ",
        "name=\"/dev/video0\" pid=167490 comm=\"prueba-vasak.Ap\" ",
        "requested_mask=\"r\" denied_mask=\"r\" fsuid=1000 ouid=0"
    );

    #[test]
    fn una_denegacion_real_se_interpreta_entera() {
        let d = parsear(REAL).expect("tendría que reconocerla");
        assert_eq!(d.perfil, "vasak-appimage");
        assert_eq!(d.ruta, "/dev/video0");
        assert_eq!(d.pid, 167490);
        assert_eq!(d.uid, 1000);
    }

    /// El caso que hace fácil equivocarse: `fsuid`, `ouid` y `pid` conviven en
    /// la misma línea y terminan en las mismas letras.
    #[test]
    fn no_confunde_fsuid_con_ouid() {
        let d = parsear(REAL).unwrap();
        assert_eq!(d.uid, 1000, "tomó el ouid en lugar del fsuid");
    }

    #[test]
    fn lo_permitido_no_es_una_denegacion() {
        let permitido = REAL.replace("DENIED", "ALLOWED");
        assert_eq!(parsear(&permitido), None);
    }

    /// El paquete `apparmor` trae 145 perfiles de terceros. Avisar de sus
    /// bloqueos sería hablar de decisiones que no tomamos nosotros.
    #[test]
    fn los_perfiles_ajenos_se_ignoran() {
        let ajeno = REAL.replace("vasak-appimage", "usr.bin.man");
        assert_eq!(parsear(&ajeno), None);
    }

    #[test]
    fn una_linea_cualquiera_del_kernel_no_confunde() {
        assert_eq!(parsear("usb 1-2: new high-speed USB device"), None);
        assert_eq!(parsear(""), None);
        assert_eq!(parsear("apparmor=\"DENIED\" sin nada más"), None);
    }

    #[test]
    fn las_rutas_se_traducen_al_recurso_que_son() {
        assert_eq!(recurso_de("/dev/video0"), Some(Resource::Camera));
        assert_eq!(recurso_de("/dev/video42"), Some(Resource::Camera));
        assert_eq!(recurso_de("/dev/snd/pcmC0D0c"), Some(Resource::Microphone));
    }

    /// Los de reproducción terminan en `p` y el perfil no los niega: si
    /// apareciera uno acá, avisar de un micrófono sería mentir.
    #[test]
    fn un_dispositivo_de_reproduccion_no_es_el_microfono() {
        assert_eq!(recurso_de("/dev/snd/pcmC0D0p"), None);
        assert_eq!(recurso_de("/dev/snd/controlC0"), None);
    }

    #[test]
    fn una_ruta_que_no_reconocemos_no_inventa_un_recurso() {
        assert_eq!(recurso_de("/home/alguien/archivo"), None);
        assert_eq!(recurso_de(""), None);
    }
}
