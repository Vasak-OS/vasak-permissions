//! El aviso de que AppArmor bloqueó algo.
//!
//! No pregunta ni decide nada: informa. El bloqueo ya ocurrió —lo hizo el
//! kernel, con el perfil que trae el sistema— y no se puede deshacer desde acá.
//!
//! Existe porque un bloqueo silencioso es casi tan malo como no tenerlo. Sin
//! esto, lo que la persona ve es una cámara que no funciona: va a culpar al
//! hardware, o a la aplicación, y va a terminar desinstalando algo que no
//! estaba roto. Decirle qué pasó y por qué es la diferencia entre una decisión
//! del sistema y una falla aparente.
//!
//! Va como notificación de escritorio y no como diálogo a propósito: un diálogo
//! interrumpe y exige una respuesta que acá no hay que dar.

use tauri::AppHandle;
use tauri_plugin_i18n_vsk::PluginI18nExt;
use vasak_permissions_protocol::{PermissionRequest, Resource};

/// El icono de cada recurso, con nombres del tema de iconos.
fn icono_de(resource_id: &str) -> &'static str {
    match resource_id {
        "microphone" => "audio-input-microphone",
        "credentials" => "dialog-password",
        "file" => "dialog-warning",
        _ => "camera-web",
    }
}

/// Si este aviso es de un recurso del que sabemos hablar.
///
/// El método de D-Bus que recibe los avisos está expuesto en el bus del
/// sistema, así que en principio lo puede llamar cualquier proceso local y no
/// sólo el servicio de permisos. Sin esto, alguien podría hacer aparecer una
/// notificación con la marca de VasakOS y el texto que quisiera.
///
/// Se aceptan los recursos que los perfiles de AppArmor niegan, que son los
/// únicos para los que hay texto traducido: cualquier otro terminaría mostrando
/// la clave cruda.
pub fn se_avisa_de(resource_id: &str) -> bool {
    // `file` no es un `Resource` y no debe serlo: el sujeto del aviso es una
    // ruta, y una variante que lleve una ruta adentro tendría cardinalidad
    // infinita y se colaría en el almacén de decisiones y en la lista de
    // recursos de Configuración. Se acepta acá, que es donde importa: hay texto
    // traducido para él.
    if resource_id == "file" {
        return true;
    }
    matches!(
        Resource::from_id(resource_id),
        Some(Resource::Camera) | Some(Resource::Microphone) | Some(Resource::Credentials)
    )
}

/// El texto del aviso, ya traducido y con el nombre de la aplicación puesto.
///
/// Separado del envío para poder comprobarlo sin un bus de por medio. La
/// interpolación va con `replace` porque el `t()` del plugin no interpola: pone
/// `{0}` tal cual.
pub fn texto(plantilla: &str, nombre_de_la_app: &str) -> String {
    plantilla.replace("{0}", nombre_de_la_app)
}

/// Igual, con un segundo dato: la ruta que se bloqueó.
///
/// Va en el cuerpo y no en el título porque una ruta larga empujaría afuera el
/// nombre de la aplicación, que es lo primero que la persona necesita leer.
pub fn texto_con_detalle(plantilla: &str, nombre_de_la_app: &str, detalle: &str) -> String {
    plantilla
        .replace("{0}", nombre_de_la_app)
        .replace("{1}", detalle)
}

// ── Decidir desde el propio aviso ────────────────────────────────────────────

/// Qué se decide si alguien aprieta un botón del aviso.
///
/// Se guarda por identificador de notificación porque es lo único que
/// `ActionInvoked` trae: la señal dice qué notificación y qué botón, nada más.
#[derive(Clone)]
pub struct Pendiente {
    pub resource_id: String,
    pub detail: String,
    pub profile: String,
    pub binary_path: String,
}

pub type Avisados = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u32, Pendiente>>>;

/// Cuántos avisos se recuerdan a la vez.
///
/// Sin techo, un aluvión de bloqueos dejaría el mapa creciendo para siempre con
/// avisos que nadie va a contestar. Al llenarse se olvida el más viejo: si
/// alguien aprieta un botón de un aviso ya olvidado, no pasa nada y la decisión
/// sigue disponible en Configuración, que es donde de verdad vive.
const AVISOS_RECORDADOS: usize = 32;

fn recordar(avisados: &Avisados, id: u32, pendiente: Pendiente) {
    let Ok(mut mapa) = avisados.lock() else { return };
    if mapa.len() >= AVISOS_RECORDADOS {
        if let Some(&viejo) = mapa.keys().min() {
            mapa.remove(&viejo);
        }
    }
    mapa.insert(id, pendiente);
}

/// Si el daemon de notificaciones sabe mostrar botones.
///
/// Se pregunta en vez de darlo por hecho: no todos los daemons los soportan, y
/// mandar botones a uno que no puede mostrarlos deja un aviso que promete una
/// decisión que no se puede tomar. Ahí es mejor el aviso a secas, que ya manda
/// a Configuración.
pub async fn hay_botones(connection: &zbus::Connection) -> bool {
    let Ok(reply) = connection
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "GetCapabilities",
            &(),
        )
        .await
    else {
        return false;
    };
    reply
        .body()
        .deserialize::<Vec<String>>()
        .map(|c| c.iter().any(|x| x == "actions"))
        .unwrap_or(false)
}

/// Las claves de los botones. Viajan por el bus, así que se nombran una vez.
pub const ACCION_PERMITIR: &str = "permitir";
pub const ACCION_NO: &str = "no";

/// Muestra el aviso.
///
/// Si algo falla —no hay daemon de notificaciones, no hay bus de sesión— se
/// registra y se sigue. Un aviso perdido no justifica romper nada.
pub async fn mostrar(app: &AppHandle, aviso: &PermissionRequest, avisados: &Avisados) {
    let clave = format!("blocked.{}", aviso.resource_id);
    let plantilla = app
        .i18n()
        .translate(&clave)
        .unwrap_or(&clave)
        .to_string();
    let resumen = texto(&plantilla, &aviso.application.display_name);
    // El cuerpo, con uno propio por recurso si lo hay.
    //
    // El general habla de la cámara y el micrófono, y para un bloqueo de
    // credenciales sería directamente falso — diría que se impidió el acceso a
    // la cámara cuando lo que se impidió fue leer tus claves. Un aviso que
    // explica mal lo que pasó es peor que uno escueto.
    let cuerpo = {
        let plantilla = app
            .i18n()
            .translate(&format!("blocked.body-{}", aviso.resource_id))
            .or_else(|| app.i18n().translate("blocked.body"))
            .unwrap_or("")
            .to_string();
        texto_con_detalle(&plantilla, &aviso.application.display_name, &aviso.detail)
    };

    let connection = match zbus::Connection::session().await {
        Ok(connection) => connection,
        Err(error) => {
            eprintln!("[vasak-permissions-agent] sin bus de sesión para avisar: {error}");
            return;
        }
    };

    // Los botones, si el daemon sabe mostrarlos. Van en pares: clave, etiqueta.
    //
    // «Permitir» pide la contraseña de administrador cuando se aprieta, porque
    // conceder pasa por polkit. Por eso la etiqueta no promete que sea
    // inmediato: quien la lea tiene que esperar que le pregunten.
    let etiquetas = (
        traducir(app, "blocked.allow"),
        traducir(app, "blocked.deny"),
    );
    let acciones: Vec<&str> = if hay_botones(&connection).await {
        vec![ACCION_PERMITIR, &etiquetas.0, ACCION_NO, &etiquetas.1]
    } else {
        Vec::new()
    };

    // La firma de org.freedesktop.Notifications.Notify. El 0 de `replaces_id`
    // es «no reemplaces ninguna anterior», y el -1 de `expire_timeout` deja que
    // el daemon decida cuánto dura.
    let argumentos = (
        "VasakOS",
        0u32,
        icono_de(&aviso.resource_id),
        resumen.as_str(),
        cuerpo.as_str(),
        acciones.clone(),
        std::collections::HashMap::<&str, zbus::zvariant::Value>::new(),
        -1i32,
    );
    match connection
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &argumentos,
        )
        .await
    {
        Ok(reply) => {
            // Sin botones no hay nada que recordar: nadie va a apretar nada.
            if acciones.is_empty() {
                return;
            }
            if let Ok(id) = reply.body().deserialize::<u32>() {
                recordar(
                    avisados,
                    id,
                    Pendiente {
                        resource_id: aviso.resource_id.clone(),
                        detail: aviso.detail.clone(),
                        profile: aviso.profile.clone(),
                        binary_path: aviso.application.binary_path.clone(),
                    },
                );
            }
        }
        Err(error) => {
            eprintln!("[vasak-permissions-agent] no se pudo mostrar el aviso: {error}");
        }
    }
}

fn traducir(app: &AppHandle, clave: &str) -> String {
    app.i18n().translate(clave).unwrap_or(clave).to_string()
}

/// Escucha los botones del aviso y ejecuta lo que se apretó.
///
/// Nunca termina; se lanza como tarea de fondo. Si la señal no se puede
/// suscribir, se registra y se sale: sin esto los botones no hacen nada, pero
/// el aviso sigue mostrándose y Configuración sigue funcionando.
///
/// `sistema` es la conexión al servicio de permisos, que vive en el bus del
/// sistema; los avisos y sus botones están en el de sesión. Un proceso, dos
/// buses, porque los dos trabajos viven en lugares distintos.
pub async fn escuchar_botones(
    sesion: zbus::Connection,
    sistema: zbus::Connection,
    avisados: Avisados,
) {
    use futures_util::StreamExt;

    let mut flujo = match zbus::MessageStream::for_match_rule(
        zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("org.freedesktop.Notifications")
            .and_then(|b| b.member("ActionInvoked"))
            .expect("la regla de coincidencia está escrita a mano y es válida")
            .build(),
        &sesion,
        None,
    )
    .await
    {
        Ok(flujo) => flujo,
        Err(error) => {
            eprintln!("[vasak-permissions-agent] sin señales de los botones: {error}");
            return;
        }
    };

    while let Some(Ok(mensaje)) = flujo.next().await {
        let Ok((id, accion)) = mensaje.body().deserialize::<(u32, String)>() else {
            continue;
        };
        // Se saca del mapa al atenderlo: el daemon puede repetir la señal si la
        // persona apreta dos veces, y conceder dos veces pediría la contraseña
        // dos veces para nada.
        let Some(pendiente) = avisados.lock().ok().and_then(|mut m| m.remove(&id)) else {
            continue;
        };
        atender(&sistema, &accion, &pendiente).await;
    }
}

/// Hace lo que el botón dice.
///
/// Un bloqueo genérico se decide por perfil y ruta; uno de un recurso con
/// nombre, por programa y recurso. Son dos caminos porque son dos cosas: el
/// primero autoriza un archivo concreto, el segundo una capacidad.
async fn atender(sistema: &zbus::Connection, accion: &str, pendiente: &Pendiente) {
    let generico = !pendiente.profile.is_empty();

    let resultado = match (accion, generico) {
        (ACCION_PERMITIR, true) => llamar(
            sistema,
            "AllowBlocked",
            &(pendiente.profile.as_str(), pendiente.detail.as_str()),
        )
        .await,
        (ACCION_NO, true) => llamar(
            sistema,
            "DismissBlocked",
            &(pendiente.profile.as_str(), pendiente.detail.as_str()),
        )
        .await,
        (ACCION_PERMITIR, false) => llamar(
            sistema,
            "SetPermission",
            &(pendiente.binary_path.as_str(), pendiente.resource_id.as_str(), true),
        )
        .await,
        (ACCION_NO, false) => llamar(
            sistema,
            "SetPermission",
            &(pendiente.binary_path.as_str(), pendiente.resource_id.as_str(), false),
        )
        .await,
        _ => return, // otro botón, o el «default» de algunos daemons
    };

    if let Err(error) = resultado {
        // Que la autenticación se rechace es lo normal, no una falla. Queda en
        // el diario y nada más: no hay dónde mostrar un error de un aviso que
        // ya se cerró, y la decisión sigue disponible en Configuración.
        eprintln!("[vasak-permissions-agent] no se pudo aplicar «{accion}»: {error}");
    }
}

async fn llamar<A>(sistema: &zbus::Connection, metodo: &str, argumentos: &A) -> zbus::Result<()>
where
    A: serde::Serialize + zbus::zvariant::DynamicType + Sync,
{
    sistema
        .call_method(
            Some(vasak_permissions_protocol::SERVICE_NAME),
            vasak_permissions_protocol::SERVICE_PATH,
            Some(vasak_permissions_protocol::SERVICE_INTERFACE),
            metodo,
            argumentos,
        )
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El aviso genérico: el sujeto es una ruta, no un recurso con nombre.
    #[test]
    fn se_avisa_de_un_bloqueo_de_archivo() {
        assert!(se_avisa_de("file"));
    }

    /// Y el cuerpo pone las dos cosas: quién y qué archivo.
    #[test]
    fn el_cuerpo_lleva_la_aplicacion_y_la_ruta() {
        let texto = texto_con_detalle(
            "Un perfil le impidió abrir {1}. Fue {0}.",
            "Firefox",
            "/etc/shadow",
        );
        assert_eq!(texto, "Un perfil le impidió abrir /etc/shadow. Fue Firefox.");
    }

    /// Una plantilla a la que le falte un marcador no puede romper el aviso ni
    /// dejar un «{1}» a la vista de la persona.
    #[test]
    fn una_plantilla_incompleta_no_deja_marcadores_sueltos() {
        assert_eq!(texto_con_detalle("Se bloqueó algo", "App", "/x"), "Se bloqueó algo");
        assert_eq!(texto_con_detalle("{0} falló", "App", "/x"), "App falló");
    }

    #[test]
    fn el_nombre_de_la_aplicacion_reemplaza_al_marcador() {
        assert_eq!(
            texto("{0} quiso usar la cámara", "App Monitor"),
            "App Monitor quiso usar la cámara"
        );
    }

    /// Si la traducción no tuviera el marcador, el aviso igual tiene que salir
    /// —incompleto, pero no vacío ni con un `{0}` a la vista—.
    #[test]
    fn una_plantilla_sin_marcador_no_rompe() {
        assert_eq!(texto("Se bloqueó la cámara", "App"), "Se bloqueó la cámara");
    }

    #[test]
    fn solo_se_avisa_de_lo_que_los_perfiles_niegan() {
        assert!(se_avisa_de("camera"));
        assert!(se_avisa_de("microphone"));
    }

    /// Lo demás no: no hay texto traducido para esos recursos, y el método está
    /// expuesto en el bus del sistema.
    #[test]
    fn no_se_avisa_de_cualquier_cosa_que_llegue_por_el_bus() {
        assert!(!se_avisa_de("screen-capture"));
        assert!(!se_avisa_de("location"));
        assert!(!se_avisa_de("account.email"));
        assert!(!se_avisa_de("inventado"));
        assert!(!se_avisa_de(""));
    }

    #[test]
    fn cada_recurso_lleva_su_icono() {
        assert_eq!(icono_de("microphone"), "audio-input-microphone");
        assert_eq!(icono_de("camera"), "camera-web");
    }
}