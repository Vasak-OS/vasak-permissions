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
/// Se aceptan los dos recursos que los perfiles de AppArmor niegan, que son los
/// únicos para los que hay texto traducido: cualquier otro terminaría mostrando
/// la clave cruda.
pub fn se_avisa_de(resource_id: &str) -> bool {
    matches!(
        Resource::from_id(resource_id),
        Some(Resource::Camera) | Some(Resource::Microphone)
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

/// Muestra el aviso.
///
/// Si algo falla —no hay daemon de notificaciones, no hay bus de sesión— se
/// registra y se sigue. Un aviso perdido no justifica romper nada.
pub async fn mostrar(app: &AppHandle, aviso: &PermissionRequest) {
    let clave = format!("blocked.{}", aviso.resource_id);
    let plantilla = app
        .i18n()
        .translate(&clave)
        .unwrap_or(&clave)
        .to_string();
    let resumen = texto(&plantilla, &aviso.application.display_name);
    let cuerpo = app
        .i18n()
        .translate("blocked.body")
        .unwrap_or("")
        .to_string();

    let connection = match zbus::Connection::session().await {
        Ok(connection) => connection,
        Err(error) => {
            eprintln!("[vasak-permissions-agent] sin bus de sesión para avisar: {error}");
            return;
        }
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
        Vec::<&str>::new(),
        std::collections::HashMap::<&str, zbus::zvariant::Value>::new(),
        -1i32,
    );
    if let Err(error) = connection
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &argumentos,
        )
        .await
    {
        eprintln!("[vasak-permissions-agent] no se pudo mostrar el aviso: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
