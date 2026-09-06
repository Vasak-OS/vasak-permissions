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
    /// Cuándo ocurrió, según el propio registro del kernel.
    ///
    /// Hace falta para elegir bien en la caché de procesos: sin esto, un pid
    /// reciclado devolvería la aplicación que heredó el número en vez de la que
    /// fue bloqueada.
    pub momento: std::time::Duration,
    /// Qué permisos se le negaron, tal como los informa el kernel.
    ///
    /// Hace falta para conceder exactamente eso y no más: un programa al que
    /// se le negó leer un archivo no necesita poder escribirlo, y una
    /// excepción que conceda `rw` porque es más fácil da más de lo que se
    /// pidió.
    pub mascara: String,
}

/// El perfil general, el que confina a toda aplicación sin excepción propia.
const PERFIL_GENERAL: &str = "vasak-appimage";

/// Si el bloqueo lo produjo un perfil nuestro.
///
/// Se filtra porque el sistema trae más de quinientos perfiles de terceros, y
/// avisar de los suyos sería ruido sobre decisiones que no tomamos nosotros.
///
/// Los de excepción cuentan igual que el general, y omitirlos era un agujero
/// silencioso: apenas se le concede algo a una aplicación se le escribe su
/// propio perfil, y desde ahí el kernel informa **ese** nombre. Con el filtro
/// mirando sólo el general, conceder la cámara dejaba mudos todos los demás
/// bloqueos de esa aplicación —se le negaba la clave de SSH, no aparecía aviso
/// ni entrada en la lista, y no había forma de concederle nada más—. Conceder
/// un permiso no puede apagar los avisos de los otros.
fn es_nuestro(perfil: &str) -> bool {
    perfil == PERFIL_GENERAL || perfil.starts_with(crate::excepcion::PREFIJO)
}

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
/// Devuelve `None` para todo lo que no sea una denegación, que es la enorme
/// mayoría de lo que pasa por ahí.
///
/// Los perfiles ajenos **ya no se descartan acá**. Se clasifican después, con
/// [`es_nuestro`]: los nuestros van al flujo de recursos con nombre —cámara,
/// micrófono, credenciales— y los demás al genérico, donde lo que se ofrece
/// desbloquear es la ruta concreta. Descartarlos era lo que dejaba a los más de
/// mil quinientos perfiles del sistema bloqueando sin aviso y sin remedio.
///
/// Sólo `DENIED`: en modo aviso el kernel escribe `ALLOWED`, y avisar de algo
/// que no se bloqueó sería ruido sobre una decisión que no ocurrió.
pub fn parsear(linea: &str) -> Option<Denegacion> {
    if texto_de(linea, "apparmor")? != "DENIED" {
        return None;
    }
    let perfil = texto_de(linea, "profile")?;
    Some(Denegacion {
        perfil: perfil.to_string(),
        ruta: texto_de(linea, "name")?.to_string(),
        pid: numero_de(linea, "pid")?,
        // `fsuid` y no `ouid`: el primero es quién intentó, el segundo de quién
        // es el archivo. Para saber a quién avisarle hace falta el primero.
        uid: numero_de(linea, "fsuid")?,
        momento: momento_de(linea).unwrap_or_default(),
        // Si el kernel no la trae, `r` es la suposición más chica: se concede
        // lo mínimo y, si hacía falta más, vuelve a aparecer un bloqueo.
        mascara: texto_de(linea, "denied_mask").unwrap_or("r").to_string(),
    })
}

/// Cuándo ocurrió la denegación, según la marca del propio registro.
///
/// El kernel la escribe como `audit(1788539628.817:36077)`: segundos desde el
/// epoch, con milésimas, y después un número de serie que acá no interesa.
///
/// Se leen los dos campos como enteros, sin pasar por punto flotante. La
/// versión anterior hacía `Duration::from_secs_f64` de lo que hubiera parseado,
/// y esa función **entra en pánico** con `NaN`, con infinito y con cualquier
/// valor que no entre en un `u64` — las tres cosas que `"inf".parse::<f64>()`,
/// `"NaN"` y `"1e30"` producen sin ser negativas, así que la guarda de signo no
/// las tocaba. Un pánico acá se lleva el hilo que lee el registro del kernel, y
/// a partir de ahí ningún bloqueo se vuelve a avisar: el resto del servicio
/// sigue en pie, así que la falla sería muda.
pub fn momento_de(linea: &str) -> Option<std::time::Duration> {
    let inicio = linea.find("audit(")? + "audit(".len();
    let resto = &linea[inicio..];
    let fin = resto.find(':')?;
    let marca = &resto[..fin];

    let (enteros, decimales) = match marca.split_once('.') {
        Some((e, d)) => (e, d),
        None => (marca, ""),
    };

    let segundos: u64 = enteros.parse().ok()?;
    // Las milésimas vienen con tres dígitos, pero no se da por sentado: se
    // normaliza a tres para que `.8` no se lea como 8 ms en vez de 800.
    let milesimas: u32 = if decimales.is_empty() {
        0
    } else {
        if !decimales.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let tres: String = decimales.chars().chain("000".chars()).take(3).collect();
        tres.parse().ok()?
    };

    Some(std::time::Duration::new(segundos, milesimas * 1_000_000))
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
    if es_credencial(ruta) {
        return Some(Resource::Credentials);
    }
    None
}

/// Los sufijos que el kernel informa cuando se bloquea algo que prueba quién
/// sos.
///
/// Se comparan **contra el final de la ruta absoluta** y no contra `@{HOME}`,
/// porque el registro del kernel trae la ruta ya resuelta: `/home/ana/.ssh/id`,
/// no la variable del perfil. Y se comparan por segmento —con la barra
/// delante— para que `/home/ana/proyecto/.sshconfig` no cuente como `.ssh`.
///
/// La lista tiene que ser la misma que niega `excepcion::NEGACIONES`. Si allá
/// se agrega una ruta y acá no, el bloqueo ocurre y nadie se entera: la persona
/// ve una aplicación que falla sin explicación, que es exactamente lo que este
/// aviso existe para evitar.
const CREDENCIALES: &[&str] = &[
    "/.ssh/",
    "/.gnupg/",
    "/.local/share/vasak-keyring/",
    "/ssh-agent.socket",
    "/gnupg/",
    "/.netrc",
    "/.git-credentials",
    "/.npmrc",
    "/.aws/",
    "/.kube/",
    "/.config/gh/",
    "/.docker/config.json",
];

fn es_credencial(ruta: &str) -> bool {
    CREDENCIALES.iter().any(|marca| {
        if marca.ends_with('/') {
            ruta.contains(marca)
        } else {
            // Sin barra final es un archivo concreto: tiene que terminar ahí,
            // para que `/home/ana/.netrc.bak` no cuente.
            ruta.ends_with(marca)
        }
    })
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
pub async fn vigilar(
    connection: zbus::Connection,
    agents: crate::agent::SharedAgents,
    store: crate::policy::PolicyStore,
    write_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    procesos: crate::procesos::Cache,
    pendientes: crate::local::Pendientes,
) {
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
        // Un bloqueo de un perfil ajeno —de los más de mil quinientos que trae
        // el sistema— no tiene un recurso con nombre: lo que se puede ofrecer
        // desbloquear es la ruta concreta. Antes se descartaba, y eso dejaba a
        // la persona con un programa que falla sin explicación y sin remedio.
        if !es_nuestro(&denegacion.perfil) {
            let programa = crate::procesos::recordada(&procesos, denegacion.pid, denegacion.momento)
                .map(|r| r.to_string_lossy().into_owned())
                .unwrap_or_default();
            let primera_vez = crate::local::anotar(
                &pendientes,
                crate::local::Bloqueo {
                    uid: denegacion.uid,
                    perfil: denegacion.perfil.clone(),
                    ruta: denegacion.ruta.clone(),
                    mascara: denegacion.mascara.clone(),
                    programa: programa.clone(),
                    veces: 1,
                },
            );

            // Se avisa la primera vez y no en cada reintento. Un programa
            // bloqueado suele reintentar en bucle, y una notificación por
            // intento haría que la persona apague los avisos — con lo cual el
            // próximo, el que sí importaba, tampoco se vería.
            if primera_vez {
                let aplicacion = crate::identity::describe_path(if programa.is_empty() {
                    &denegacion.perfil
                } else {
                    &programa
                });
                // En una tarea aparte y con cupo, igual que los avisos de
                // recursos con nombre. Esperando acá, un daemon de
                // notificaciones lento o ausente frenaría la lectura del
                // registro del kernel —que no espera a nadie y sigue rotando—,
                // y se perderían denegaciones por esperar a una notificación.
                match cupo().clone().try_acquire_owned() {
                    Ok(permiso) => {
                        let connection = connection.clone();
                        let agents = agents.clone();
                        let uid = denegacion.uid;
                        let ruta = denegacion.ruta.clone();
                        let perfil = denegacion.perfil.clone();
                        tokio::spawn(async move {
                            let _permiso = permiso;
                            crate::agent::avisar_de_archivo(
                                &connection, &agents, uid, &aplicacion, &perfil, &ruta,
                            )
                            .await;
                        });
                    }
                    Err(_) => tracing::debug!("Demasiados avisos a la vez; se descarta uno"),
                }
            }
            continue;
        }

        let Some(recurso) = recurso_de(&denegacion.ruta) else {
            // Un perfil **nuestro** negó algo que este módulo no sabe nombrar.
            // Vale la pena que quede escrito: significa que el perfil y esto se
            // desincronizaron, que es la falla muda que las pruebas cuidan.
            tracing::warn!(
                "El perfil '{}' bloqueó '{}', que no sé a qué recurso corresponde",
                denegacion.perfil,
                denegacion.ruta
            );
            continue;
        };

        // El proceso suele estar vivo, y entonces se lo identifica directo.
        //
        // Pero muchas veces ya no está, **precisamente porque se le negó lo que
        // necesitaba**: a un programa al que le cortan la cámara es normal que
        // salga en el acto. Para ese caso está la caché, que anotó su ruta
        // cuando arrancó. Sin ella, el caso más común se perdía entero: ni
        // aviso ni anotación, y la aplicación no aparecía nunca en la lista,
        // así que no había forma de concederle nada.
        let aplicacion = match crate::identity::PinnedCaller::capture(
            denegacion.pid,
            denegacion.uid,
        ) {
            Ok(proceso) => proceso.describe(),
            Err(_) => match crate::procesos::recordada(&procesos, denegacion.pid, denegacion.momento) {
                Some(ruta) => {
                    tracing::debug!(
                        "El proceso {} ya no está; se lo nombra por lo recordado",
                        denegacion.pid
                    );
                    crate::identity::describe_path(&ruta.to_string_lossy())
                }
                None => {
                    // Ni vivo ni recordado. Un aviso que no nombra a nadie
                    // asusta sin informar, así que no se manda.
                    tracing::info!(
                        "Se bloqueó '{}' al proceso {}, que ya no existe y no se recuerda",
                        denegacion.ruta,
                        denegacion.pid
                    );
                    continue;
                }
            },
        };

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

        // Dejar constancia de que esta aplicación quiso el recurso.
        //
        // Sin esto el aviso es lo único que queda, y desaparece de la pantalla
        // en unos segundos: la aplicación no aparecería en la lista de permisos
        // y no habría desde dónde permitirle nada. Registrarla es lo que
        // convierte un bloqueo en algo sobre lo que después se puede decidir.
        //
        // Sólo cuando no había decisión previa. Si alguien ya dijo que no, esto
        // no agrega nada; y si dijo que sí, escribir «denegado» acá borraría su
        // decisión por un bloqueo que probablemente venga de que la excepción
        // todavía no estaba cargada.
        registrar_el_intento(&store, &write_lock, denegacion.uid, &aplicacion, &recurso).await;

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

/// Anota en la política que esta aplicación pidió el recurso y no lo tenía.
async fn registrar_el_intento(
    store: &crate::policy::PolicyStore,
    write_lock: &std::sync::Arc<tokio::sync::Mutex<()>>,
    uid: u32,
    aplicacion: &vasak_permissions_protocol::Application,
    recurso: &Resource,
) {
    use vasak_permissions_protocol::Decision;

    // El mismo candado que usan las respuestas del diálogo: sin él, dos
    // escrituras a la vez se pisan y una decisión se pierde.
    let _guard = write_lock.lock().await;
    let mut politica = match store.load(uid) {
        Ok(politica) => politica,
        Err(error) => {
            tracing::warn!("No se pudo leer la política del usuario {uid}: {error}");
            return;
        }
    };
    if politica.decision(&aplicacion.binary_path, &recurso.as_id()) != Decision::Unknown {
        return;
    }
    politica.record(aplicacion, &recurso.as_id(), Decision::Denied);
    if let Err(error) = store.save(uid, &politica) {
        tracing::warn!("No se pudo anotar el bloqueo de {}: {error}", aplicacion.binary_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use vasak_permissions_protocol::{Application, Decision, Provenance};

    fn una_app(ruta: &str) -> Application {
        Application {
            binary_path: ruta.to_string(),
            display_name: "prueba".into(),
            provenance: Provenance::Unverified,
        }
    }

    async fn registrar_en(
        store: &crate::policy::PolicyStore,
        app: &Application,
        recurso: &Resource,
    ) {
        let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        registrar_el_intento(store, &lock, 1000, app, recurso).await;
    }

    /// Sin esto la aplicación bloqueada no aparece en ninguna lista y no hay
    /// desde dónde permitirle nada: el bloqueo sería definitivo por omisión.
    #[tokio::test]
    async fn un_bloqueo_deja_a_la_aplicacion_anotada() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::policy::PolicyStore::at(dir.path().to_path_buf());
        let app = una_app("/home/x/a.AppImage");

        registrar_en(&store, &app, &Resource::Camera).await;

        let politica = store.load(1000).unwrap();
        assert_eq!(
            politica.decision("/home/x/a.AppImage", "camera"),
            Decision::Denied
        );
    }

    /// Lo más importante: si alguien ya dijo que sí, un bloqueo no puede
    /// borrarlo. Un bloqueo con el permiso concedido suele significar que la
    /// excepción todavía no estaba cargada, no que la persona cambió de idea.
    #[tokio::test]
    async fn no_pisa_una_decision_ya_tomada() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::policy::PolicyStore::at(dir.path().to_path_buf());
        let app = una_app("/home/x/a.AppImage");

        let mut politica = store.load(1000).unwrap();
        politica.record(&app, "camera", Decision::Allowed);
        store.save(1000, &politica).unwrap();

        registrar_en(&store, &app, &Resource::Camera).await;

        assert_eq!(
            store.load(1000).unwrap().decision("/home/x/a.AppImage", "camera"),
            Decision::Allowed,
            "el bloqueo borró un permiso que la persona había concedido"
        );
    }

    #[tokio::test]
    async fn cada_recurso_se_anota_por_separado() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::policy::PolicyStore::at(dir.path().to_path_buf());
        let app = una_app("/home/x/a.AppImage");

        registrar_en(&store, &app, &Resource::Microphone).await;

        let politica = store.load(1000).unwrap();
        assert_eq!(politica.decision("/home/x/a.AppImage", "microphone"), Decision::Denied);
        assert_eq!(politica.decision("/home/x/a.AppImage", "camera"), Decision::Unknown);
    }

    /// Una línea tal cual la escribe el kernel, copiada del registro real.
    const REAL: &str = concat!(
        "audit: type=1400 audit(1788539628.817:36077): apparmor=\"DENIED\" ",
        "operation=\"open\" class=\"file\" profile=\"vasak-appimage\" ",
        "name=\"/dev/video0\" pid=167490 comm=\"prueba-vasak.Ap\" ",
        "requested_mask=\"r\" denied_mask=\"r\" fsuid=1000 ouid=0"
    );

    /// Una marca imposible no debe tumbar el hilo que lee el registro. Antes
    /// las tres pasaban la guarda de signo y hacían entrar en pánico a
    /// `Duration::from_secs_f64`; el aviso de bloqueos quedaba muerto en
    /// silencio para el resto de la sesión.
    /// Las rutas que el kernel informa cuando se bloquea una credencial.
    /// El bloqueo bajo un perfil de excepción tiene que llegar igual.
    ///
    /// Apenas se le concede algo a una aplicación se le escribe su propio
    /// perfil, y a partir de ahí el kernel informa **ese** nombre. Si el filtro
    /// sólo acepta el general, conceder la cámara deja mudos todos los demás
    /// bloqueos de esa aplicación: se le niega la clave de SSH, no aparece
    /// aviso, no aparece en la lista, y no hay forma de concederle nada más.
    /// Conceder un permiso no puede apagar los avisos de los otros.
    #[test]
    fn un_bloqueo_bajo_un_perfil_de_excepcion_no_se_descarta() {
        let nombre = crate::excepcion::nombre_de("/home/ana/Apps/cosa.AppImage");
        let linea = format!(
            "audit(1788539628.817:36077): apparmor=\"DENIED\" operation=\"open\" \
             profile=\"{nombre}\" name=\"/home/ana/.ssh/id_ed25519\" pid=4242 \
             comm=\"cosa\" requested_mask=\"r\" denied_mask=\"r\" fsuid=1000 ouid=1000"
        );
        let d = parsear(&linea).expect("la denegación tiene que llegar");
        assert_eq!(d.ruta, "/home/ana/.ssh/id_ed25519");
        assert_eq!(recurso_de(&d.ruta), Some(Resource::Credentials));
    }

    #[test]
    fn una_credencial_se_reconoce() {
        for ruta in [
            "/home/ana/.ssh/id_ed25519",
            "/home/ana/.gnupg/private-keys-v1.d/x.key",
            "/home/ana/.local/share/vasak-keyring/llavero.db",
            "/run/user/1000/ssh-agent.socket",
            "/home/ana/.netrc",
            "/home/ana/.git-credentials",
            "/home/ana/.aws/credentials",
            "/home/ana/.config/gh/hosts.yml",
            "/home/ana/.docker/config.json",
        ] {
            assert_eq!(recurso_de(ruta), Some(Resource::Credentials), "{ruta}");
        }
    }

    /// Y lo que se le parece pero no lo es. Un falso positivo acá no es
    /// inofensivo: haría aparecer un aviso de robo de claves por un archivo
    /// cualquiera, y la persona aprendería a ignorarlos.
    #[test]
    fn lo_que_solo_se_parece_no_cuenta() {
        for ruta in [
            "/home/ana/proyecto/.sshconfig",
            "/home/ana/.netrc.bak",
            "/home/ana/notas/docker/config.json.ejemplo",
            "/home/ana/Descargas/gnupg.pdf",
            "/home/ana/Documentos/carta.txt",
        ] {
            assert_eq!(recurso_de(ruta), None, "{ruta}");
        }
    }

    /// La prueba que de verdad importa: que las dos listas no se separen.
    ///
    /// El perfil niega por un lado y el vigilante reconoce por otro. Si se
    /// agrega una negación allá y no acá, el bloqueo ocurre igual y **nadie se
    /// entera**: la persona ve una aplicación que falla sin explicación y sin
    /// forma de concederle nada, que es exactamente lo que este aviso existe
    /// para evitar. Es una falla muda, y las mudas son las que sobreviven.
    #[test]
    fn toda_negacion_de_credenciales_se_reconoce() {
        let reglas = crate::excepcion::NEGACIONES
            .iter()
            .find(|(recurso, _)| *recurso == Resource::Credentials)
            .expect("las credenciales están en la tabla de negaciones")
            .1;

        for regla in reglas {
            // «audit deny @{HOME}/.ssh/** rwkl,» → la ruta es el tercer campo.
            let patron = regla.split_whitespace().nth(2).expect("regla con ruta");
            let concreta = patron
                .replace("@{HOME}", "/home/ana")
                .replace("/run/user/*/", "/run/user/1000/")
                .replace("/**", "/un-archivo")
                .replace("/*", "/un-archivo");

            assert_eq!(
                recurso_de(&concreta),
                Some(Resource::Credentials),
                "el perfil niega «{patron}» y el vigilante no lo reconoce: \
                 el bloqueo sería mudo"
            );
        }
    }

    #[test]
    fn una_marca_imposible_no_entra_en_panico() {
        for marca in ["inf", "NaN", "1e30", "-inf", "99999999999999999999999"] {
            let linea = format!("audit({marca}:36077): apparmor=\"DENIED\"");
            assert_eq!(momento_de(&linea), None, "marca: {marca}");
        }
    }

    /// Y las milésimas se leen como tales, no como el número que parezcan.
    #[test]
    fn las_milesimas_valen_lo_que_dicen() {
        let de = |m: &str| momento_de(&format!("audit({m}:1):")).unwrap();
        assert_eq!(de("10.817").subsec_millis(), 817);
        assert_eq!(de("10.8").subsec_millis(), 800);
        assert_eq!(de("10.08").subsec_millis(), 80);
        assert_eq!(de("10").subsec_millis(), 0);
        assert_eq!(de("1788539628.817").as_secs(), 1_788_539_628);
    }

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
    /// La marca del registro es lo que permite elegir bien en la caché cuando un
    /// pid se recicló.
    #[test]
    fn la_hora_del_bloqueo_sale_del_registro() {
        let d = parsear(REAL).unwrap();
        assert_eq!(d.momento.as_secs(), 1788539628);
        assert!(d.momento.subsec_millis() >= 816 && d.momento.subsec_millis() <= 818);
    }

    #[test]
    fn una_linea_sin_marca_no_inventa_una_hora() {
        assert_eq!(momento_de("sin marca"), None);
        assert_eq!(momento_de("audit(sin dos puntos"), None);
    }

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

    /// Los perfiles ajenos ya **no** se descartan: se clasifican.
    ///
    /// Antes se tiraban acá, y eso era lo que dejaba a los más de mil
    /// quinientos perfiles del sistema bloqueando sin aviso y sin forma de
    /// permitir nada — la razón por la que había que tenerlos en modo aviso.
    /// Ahora llegan, y `es_nuestro` decide a qué flujo van.
    #[test]
    fn un_perfil_ajeno_llega_y_se_clasifica_como_ajeno() {
        let ajeno = REAL.replace("vasak-appimage", "usr.bin.man");
        let d = parsear(&ajeno).expect("la denegación tiene que llegar");
        assert_eq!(d.perfil, "usr.bin.man");
        assert!(!es_nuestro(&d.perfil));
    }

    /// Y los nuestros siguen distinguiéndose.
    #[test]
    fn los_nuestros_se_reconocen_como_nuestros() {
        assert!(es_nuestro("vasak-appimage"));
        assert!(es_nuestro(&crate::excepcion::nombre_de("/home/ana/x.AppImage")));
        for ajeno in ["firefox", "usr.bin.man", "dbus-system", "vasak", "appimage"] {
            assert!(!es_nuestro(ajeno), "«{ajeno}» no es nuestro");
        }
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
