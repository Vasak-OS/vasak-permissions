//! Lo que se decidió antes, para los pedidos que llegan por el portal.
//!
//! # Qué pasaba
//!
//! El diálogo del portal preguntaba y tiraba la respuesta. Medido con Chrome
//! pidiendo compartir la pantalla:
//!
//! ```text
//! 16:26:34  el portal pide '¿Le permitís compartir tu pantalla?' (app_id 'com.google.Chrome')
//! 16:26:41  el portal pide '¿Le permitís compartir tu pantalla?' (app_id 'com.google.Chrome')
//! 16:26:48  el portal pide '¿Le permitís compartir tu pantalla?' (app_id 'com.google.Chrome')
//! 16:26:54  el portal pide '¿Le permitís compartir tu pantalla?' (app_id 'com.google.Chrome')
//! ```
//!
//! Cuatro diálogos idénticos en veinte segundos. Eso no es una protección: es
//! entrenamiento para apretar «permitir» sin leer. Y del otro lado, nada que
//! retirar — lo concedido no figuraba en ninguna parte.
//!
//! # Contra qué se guarda
//!
//! Contra el `app_id`, que es la única identidad que el portal entrega. No es
//! la ruta del ejecutable que usa el resto del servicio y no vale lo mismo: la
//! declara la propia aplicación llamando a `Register` en
//! `org.freedesktop.host.portal.Registry`, y nadie comprueba que le
//! corresponda. El crate del protocolo lo explica en `portal_key`, junto con
//! por qué se usa igual.
//!
//! # La regla que ordena todo este módulo
//!
//! **Ante la duda, preguntar.** Un `app_id` que no sirve como identidad, un
//! recurso que no se pudo nombrar, el servicio que no contesta: en todos los
//! casos se devuelve «sin decidir» y aparece el diálogo. Es exactamente lo que
//! pasaba antes de este cambio, así que lo peor que puede hacer una falla acá
//! es devolver el comportamiento viejo.
//!
//! Lo que nunca hace es lo contrario. Que el servicio no conteste no concede
//! nada: un permiso que nadie pudo autorizar no es un permiso otorgado.

use std::collections::HashMap;
use std::time::Duration;

use tauri::{AppHandle, Manager, Runtime};
use vasak_permissions_protocol::{
    Decision, PORTAL_DECISION_METHOD, RECORD_PORTAL_DECISION_METHOD, SERVICE_INTERFACE,
    SERVICE_NAME, SERVICE_PATH,
};
use zbus::zvariant::OwnedValue;

/// Lo que se espera al servicio antes de seguir sin él.
///
/// Corto a propósito. Del otro lado de esta consulta hay una aplicación
/// esperando para capturar, y el servicio está en la misma máquina leyendo un
/// archivo: si no contestó en esto, no va a contestar. Los dos minutos que el
/// servicio le da a un diálogo son para que una persona lea y piense; acá no
/// hay nadie pensando.
const ESPERA: Duration = Duration::from_secs(5);

/// El identificador del recurso, cuando se lo puede nombrar.
///
/// # Cómo se reconoce la cámara, y por qué así
///
/// `org.freedesktop.impl.portal.Access` es un diálogo genérico: el portal manda
/// título, subtítulo y cuerpo en **texto libre y traducido**, y no dice qué
/// recurso está en juego. La misma interfaz atiende la cámara, la ubicación,
/// correr en segundo plano y varias más.
///
/// Lo único legible por máquina es la opción `icon`, que para la cámara llega
/// como `camera-web-symbolic`. No es API —es un detalle de implementación de
/// `xdg-desktop-portal`— y por eso esta función devuelve `Option`: si el icono
/// cambia de nombre, acá no se reconoce nada, se pregunta cada vez y no se
/// guarda. O sea que se degrada al comportamiento de siempre en vez de romperse
/// o, mucho peor, de guardar la respuesta bajo el recurso equivocado.
///
/// Emparejar contra el título fue la otra opción y se descartó: está traducido,
/// así que dejaría de funcionar al cambiar el idioma de la sesión.
pub fn recurso_del_dialogo(options: &HashMap<String, OwnedValue>) -> Option<&'static str> {
    let icono = options.get("icon")?.downcast_ref::<String>().ok()?;

    match icono.as_str() {
        "camera-web-symbolic" | "camera-web" => Some("camera"),
        _ => None,
    }
}

/// Lo que ya se había decidido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decidido {
    Permitido,
    Negado,
    /// Nadie lo decidió todavía, o no se pudo averiguar. Hay que preguntar.
    SinDecidir,
}

impl Decidido {
    fn de(decision: Decision) -> Self {
        match decision {
            Decision::Allowed => Decidido::Permitido,
            Decision::Denied => Decidido::Negado,
            Decision::Unknown => Decidido::SinDecidir,
        }
    }
}

/// La conexión al bus del sistema que el agente ya tiene abierta.
///
/// La guarda `service::connect_and_register` en el estado de la aplicación. Que
/// todavía no esté es normal y no es un error: se registra en una tarea aparte,
/// así que un pedido del portal que llegue durante el arranque puede ganarle la
/// carrera. Se pregunta, como siempre que falta algo.
fn conexion<R: Runtime>(app: &AppHandle<R>) -> Option<zbus::Connection> {
    app.try_state::<zbus::Connection>()
        .map(|estado| estado.inner().clone())
}

/// Qué se decidió para esta aplicación y este recurso.
pub async fn consultar<R: Runtime>(
    app: &AppHandle<R>,
    app_id: &str,
    resource_id: &str,
) -> Decidido {
    let Some(connection) = conexion(app) else {
        return Decidido::SinDecidir;
    };

    let argumentos = (app_id, resource_id);
    let llamada = connection.call_method(
        Some(SERVICE_NAME),
        SERVICE_PATH,
        Some(SERVICE_INTERFACE),
        PORTAL_DECISION_METHOD,
        &argumentos,
    );

    let respuesta = match tokio::time::timeout(ESPERA, llamada).await {
        Ok(Ok(respuesta)) => respuesta,
        Ok(Err(error)) => {
            eprintln!("[vasak-permissions-agent] no se pudo consultar la política: {error}");
            return Decidido::SinDecidir;
        }
        Err(_) => {
            eprintln!("[vasak-permissions-agent] el servicio de permisos no contestó a tiempo");
            return Decidido::SinDecidir;
        }
    };

    match respuesta.body().deserialize::<String>() {
        Ok(id) => Decision::from_id(&id).map(Decidido::de).unwrap_or_else(|| {
            eprintln!("[vasak-permissions-agent] decisión ilegible del servicio: '{id}'");
            Decidido::SinDecidir
        }),
        Err(error) => {
            eprintln!("[vasak-permissions-agent] respuesta ilegible del servicio: {error}");
            Decidido::SinDecidir
        }
    }
}

/// Anota lo que la persona acaba de contestar.
///
/// No devuelve nada y no puede fallar hacia afuera a propósito. Lo que
/// gobierna el acceso es la respuesta que ya se dio, y la captura —o la cámara—
/// tiene que arrancar aunque el guardado falle: negarle el recurso a alguien
/// que dijo que sí, porque no se pudo escribir un archivo, sería cambiarle la
/// respuesta por un problema que no es suyo.
///
/// El costo de que falle es que se vuelva a preguntar la próxima vez, que es lo
/// que pasaba siempre hasta ahora.
pub async fn anotar<R: Runtime>(
    app: &AppHandle<R>,
    app_id: &str,
    resource_id: &str,
    allowed: bool,
) {
    let Some(connection) = conexion(app) else {
        return;
    };

    let argumentos = (app_id, resource_id, allowed);
    let llamada = connection.call_method(
        Some(SERVICE_NAME),
        SERVICE_PATH,
        Some(SERVICE_INTERFACE),
        RECORD_PORTAL_DECISION_METHOD,
        &argumentos,
    );

    match tokio::time::timeout(ESPERA, llamada).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            eprintln!("[vasak-permissions-agent] no se pudo guardar la decisión: {error}")
        }
        Err(_) => eprintln!(
            "[vasak-permissions-agent] el servicio no acusó la decisión a tiempo; \
             se va a volver a preguntar"
        ),
    }
}

/// Pregunta una sola vez y guarda la respuesta.
///
/// Junta las tres partes —consultar, preguntar, anotar— porque separadas se
/// pueden usar mal de una forma que no se ve leyendo: preguntar sin haber
/// consultado, o conceder sin anotar. Los dos puntos donde esto se usa hacen
/// exactamente lo mismo, así que hacen lo mismo de un solo modo.
pub async fn decidir<R: Runtime>(
    app: &AppHandle<R>,
    app_id: &str,
    resource_id: Option<&str>,
    pregunta: crate::dialog::Question,
) -> bool {
    // Sin recurso que nombrar no hay nada que guardar ni nada que consultar: se
    // pregunta, como antes de todo esto.
    let Some(resource_id) = resource_id else {
        return crate::dialog::ask(app, pregunta).await.permitio();
    };

    match consultar(app, app_id, resource_id).await {
        Decidido::Permitido => {
            // Sin diálogo. Es el punto de todo esto: quien ya contestó que sí
            // no tiene que volver a contestarlo, y si cambia de idea lo saca
            // desde Configuración.
            return true;
        }
        Decidido::Negado => {
            // Tampoco hay diálogo, y esto importa más que lo otro. Un rechazo
            // que se vuelve a preguntar no es un rechazo: es una insistencia
            // que termina cediendo.
            eprintln!(
                "[vasak-permissions-agent] '{resource_id}' ya estaba denegado para \
                 {app_id}; se rechaza sin preguntar"
            );
            return false;
        }
        Decidido::SinDecidir => {}
    }

    let respuesta = crate::dialog::ask(app, pregunta).await;

    // Sólo se guarda lo que contestó una persona.
    //
    // Que no se haya podido preguntar —otro diálogo abierto, la ventana que no
    // se pudo crear— también deniega, pero no es una decisión de nadie:
    // anotarla dejaría a la aplicación rechazada para siempre por una carrera
    // entre dos pedidos, sin que hubiera aparecido nada en pantalla.
    if respuesta.la_contesto_alguien() {
        anotar(app, app_id, resource_id, respuesta.permitio()).await;
    }

    respuesta.permitio()
}

#[cfg(test)]
mod tests {
    use super::*;

    use zbus::zvariant::Value;

    fn opciones(pares: &[(&str, &str)]) -> HashMap<String, OwnedValue> {
        pares
            .iter()
            .map(|(clave, valor)| {
                (
                    clave.to_string(),
                    OwnedValue::try_from(Value::from(*valor)).expect("valor convertible"),
                )
            })
            .collect()
    }

    /// El caso que se quiere reconocer, tal como lo manda el portal instalado.
    #[test]
    fn el_icono_de_la_camara_nombra_la_camara() {
        assert_eq!(
            recurso_del_dialogo(&opciones(&[("icon", "camera-web-symbolic")])),
            Some("camera")
        );
    }

    /// Y lo que se reconoce tiene que ser un recurso que el servicio acepte.
    ///
    /// Una cadena mal escrita acá no falla al compilar ni al correr: el servicio
    /// contestaría «recurso desconocido» y el diálogo aparecería siempre, que se
    /// ve igual que el comportamiento viejo. O sea que se rompería en silencio.
    #[test]
    fn lo_que_se_nombra_existe_como_recurso() {
        let id = recurso_del_dialogo(&opciones(&[("icon", "camera-web-symbolic")]))
            .expect("la cámara se reconoce");
        assert!(vasak_permissions_protocol::Resource::from_id(id).is_some());
    }

    /// Lo que no se reconoce no se inventa.
    ///
    /// Es la reserva segura de todo el módulo: si `xdg-desktop-portal` cambia el
    /// nombre del icono, o si el diálogo es de otra cosa —la ubicación, correr
    /// en segundo plano—, acá no sale ningún recurso y el pedido vuelve a
    /// preguntarse cada vez en vez de guardarse bajo el recurso equivocado.
    #[test]
    fn lo_desconocido_no_se_nombra() {
        assert_eq!(
            recurso_del_dialogo(&opciones(&[("icon", "mark-location-symbolic")])),
            None
        );
        assert_eq!(recurso_del_dialogo(&opciones(&[])), None);
        // Un `icon` que no es texto tampoco puede tumbar nada.
        let mut raros = HashMap::new();
        raros.insert(
            "icon".to_string(),
            OwnedValue::try_from(Value::from(42u32)).expect("valor convertible"),
        );
        assert_eq!(recurso_del_dialogo(&raros), None);
    }

    /// Las tres decisiones se traducen, y «desconocida» es la que abre diálogo.
    #[test]
    fn las_decisiones_se_traducen() {
        assert_eq!(Decidido::de(Decision::Allowed), Decidido::Permitido);
        assert_eq!(Decidido::de(Decision::Denied), Decidido::Negado);
        assert_eq!(Decidido::de(Decision::Unknown), Decidido::SinDecidir);
    }
}
