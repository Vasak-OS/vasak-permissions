//! Preguntar antes de dejar capturar la pantalla.
//!
//! # Qué pasaba
//!
//! Una aplicación que pide capturar por `org.freedesktop.portal.ScreenCast` la
//! recibía **sin que se le preguntara nada a nadie**. El portal delega el
//! diálogo al backend, y el backend era `xdg-desktop-portal-wlr`, que no tiene
//! diálogo de permiso: sólo un selector de monitor. Elegir qué pantalla
//! compartir es una elección, pero no es un permiso — no dice qué aplicación
//! pide, no se recuerda y no se puede revocar.
//!
//! Eso rompía la regla del escritorio: todo lo que se bloquea se tiene que
//! poder desbloquear, y su recíproca —todo lo que se concede se tiene que poder
//! retirar—. Acá no había nada que retirar porque no había decisión.
//!
//! # Qué hace
//!
//! Este backend se pone en el medio. Pregunta con el diálogo de VasakOS y, si
//! la respuesta es que sí, **reenvía todo** a `xdg-desktop-portal-wlr**, que es
//! el que sabe capturar la salida de un compositor wlroots. No se reimplementa
//! la captura: reimplementarla sería rehacer wlroots, PipeWire y el manejo de
//! dmabuf para no ganar nada.
//!
//! # Dónde se pregunta, y por qué ahí
//!
//! En `SelectSources` y no en `Start`. El portal llama `CreateSession` →
//! `SelectSources` → `Start`, y la última es cuando `xdpw` muestra su selector
//! de monitor. Preguntando en `SelectSources` queda la separación natural:
//! primero «¿le permitís a esta aplicación capturar?», después «¿qué pantalla?».
//! Preguntando en `Start` la persona vería las dos cosas encimadas y sin saber
//! cuál está contestando.
//!
//! # Lo que hay que reenviar y es fácil olvidar
//!
//! El portal no habla sólo por métodos. Crea una **sesión** en un camino de
//! objeto y espera que el backend la exporte ahí: si la cierra, llama a
//! `Close()` **en la nuestra**, y si la sesión muere sola espera un `Closed`.
//! Sin reenviar las dos cosas, cerrar una compartición no cerraría nada y una
//! captura terminada quedaría figurando como viva.

use std::collections::HashMap;

use tauri::{AppHandle, Runtime};
use zbus::interface;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::dialog::{PortalQuestion, Question};

/// Quién sabe capturar de verdad.
pub const WLR_NAME: &str = "org.freedesktop.impl.portal.desktop.wlr";
pub const WLR_PATH: &str = "/org/freedesktop/portal/desktop";
const SCREENCAST_IFACE: &str = "org.freedesktop.impl.portal.ScreenCast";
const SESSION_IFACE: &str = "org.freedesktop.impl.portal.Session";

const RESPONSE_GRANTED: u32 = 0;
const RESPONSE_CANCELLED: u32 = 1;
/// Algo salió mal y no fue la persona quien dijo que no.
const RESPONSE_ERROR: u32 = 2;

/// Lo que contesta un método del portal: `(response, results)`.
///
/// Sirve para leer la respuesta de `xdpw`, **no** para declarar el retorno de
/// nuestros métodos. zbus mira el tipo de retorno tal como está escrito: una
/// tupla literal la reparte en dos valores de salida —`ua{sv}`, que es lo que
/// pide la especificación— y un alias con nombre lo trata como un valor solo,
/// y lo serializa envuelto en una estructura: `(ua{sv})`.
///
/// La diferencia no se ve leyendo el código y rompe el portal entero.
pub type Respuesta = (u32, HashMap<String, OwnedValue>);

fn vacio() -> HashMap<String, OwnedValue> {
    HashMap::new()
}

/// Reenvía uno de los tres métodos a `xdg-desktop-portal-wlr`.
///
/// Separado del diálogo a propósito: así se puede probar contra el `xdpw` real
/// sin que haya que abrir una ventana ni que alguien conteste.
pub async fn reenviar<A>(connection: &zbus::Connection, metodo: &str, argumentos: &A) -> Respuesta
where
    A: serde::Serialize + zbus::zvariant::DynamicType + Sync,
{
    match connection
        .call_method(Some(WLR_NAME), WLR_PATH, Some(SCREENCAST_IFACE), metodo, argumentos)
        .await
    {
        Ok(reply) => match reply.body().deserialize::<Respuesta>() {
            Ok(r) => r,
            Err(error) => {
                eprintln!("[vasak-permissions-agent] respuesta ilegible de {metodo}: {error}");
                (RESPONSE_ERROR, vacio())
            }
        },
        Err(error) => {
            // Sin xdpw no hay captura posible. Se devuelve error y no
            // «cancelado»: cancelado significa que la persona dijo que no, y
            // decir eso cuando en realidad falló el sistema haría que quien
            // depure esto busque en el lugar equivocado.
            eprintln!("[vasak-permissions-agent] no se pudo reenviar {metodo} a wlr: {error}");
            (RESPONSE_ERROR, vacio())
        }
    }
}

/// El backend que el portal ve.
///
/// Genérico sobre el runtime de Tauri —con `Wry`, el de verdad, por omisión—
/// nada más que para poder construirlo en una prueba: `tauri::test::mock_app`
/// da un `AppHandle` de otro runtime, y sin esto no hay forma de mirar la
/// firma que esta interfaz expone por el bus. Es justo lo que hay que mirar:
/// las dos veces que estuvo mal, compilaba igual.
pub struct ScreenCastBackend<R: Runtime = tauri::Wry> {
    pub app: AppHandle<R>,
}

#[interface(name = "org.freedesktop.impl.portal.ScreenCast")]
impl<R: Runtime> ScreenCastBackend<R> {
    /// Se reenvía tal cual: crear la sesión no concede nada todavía.
    async fn create_session(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        handle: OwnedObjectPath,
        session_handle: OwnedObjectPath,
        app_id: String,
        options: HashMap<String, OwnedValue>,
    ) -> (u32, HashMap<String, OwnedValue>) {
        let respuesta = reenviar(
            connection,
            "CreateSession",
            &(&handle, &session_handle, &app_id, &options),
        )
        .await;

        // La sesión se exporta acá aunque la nuestra no haga más que reenviar:
        // el portal la busca en **nuestra** conexión, no en la de wlr.
        if respuesta.0 == RESPONSE_GRANTED {
            let sesion = SesionReenviada { destino: session_handle.clone() };
            if let Err(error) = connection.object_server().at(&session_handle, sesion).await {
                eprintln!("[vasak-permissions-agent] no se pudo exportar la sesión: {error}");
            }
        }
        respuesta
    }

    /// Acá se pregunta.
    ///
    /// Si la respuesta es que no, no se reenvía nada: `xdpw` nunca se entera de
    /// que hubo un pedido, y su selector de monitor no llega a aparecer.
    async fn select_sources(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        handle: OwnedObjectPath,
        session_handle: OwnedObjectPath,
        app_id: String,
        options: HashMap<String, OwnedValue>,
    ) -> (u32, HashMap<String, OwnedValue>) {
        let pregunta = PortalQuestion {
            app_id: app_id.clone(),
            title: traducir(&self.app, "screencast.title"),
            subtitle: traducir(&self.app, "screencast.subtitle"),
            body: traducir(&self.app, "screencast.body"),
        };

        if !crate::dialog::ask(&self.app, Question::Portal(pregunta)).await {
            return (RESPONSE_CANCELLED, vacio());
        }

        reenviar(
            connection,
            "SelectSources",
            &(&handle, &session_handle, &app_id, &options),
        )
        .await
    }

    /// Ya autorizado: acá `xdpw` muestra su selector de monitor y arranca el
    /// flujo de PipeWire. Lo que devuelve —el identificador del nodo— pasa tal
    /// cual, porque es lo que la aplicación necesita para leer la imagen.
    #[allow(clippy::too_many_arguments)]
    async fn start(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        handle: OwnedObjectPath,
        session_handle: OwnedObjectPath,
        app_id: String,
        parent_window: String,
        options: HashMap<String, OwnedValue>,
    ) -> (u32, HashMap<String, OwnedValue>) {
        reenviar(
            connection,
            "Start",
            &(&handle, &session_handle, &app_id, &parent_window, &options),
        )
        .await
    }

    /// Qué se puede capturar, según lo que dice `xdpw`.
    ///
    /// Se le pregunta a él en vez de escribir un número acá: anunciar una
    /// capacidad que el backend de atrás no tiene haría que una aplicación pida
    /// algo —capturar una ventana suelta, por ejemplo— y falle recién al
    /// intentarlo, cuando ya le dijimos que sí.
    #[zbus(property)]
    async fn available_source_types(&self) -> u32 {
        propiedad_de_wlr("AvailableSourceTypes").await.unwrap_or(1)
    }

    #[zbus(property)]
    async fn available_cursor_modes(&self) -> u32 {
        propiedad_de_wlr("AvailableCursorModes").await.unwrap_or(1)
    }

    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        // La versión que este backend implementa, no la de wlr: es lo que
        // decimos saber contestar.
        4
    }
}

/// La sesión, que sólo pasa mensajes.
struct SesionReenviada {
    destino: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.impl.portal.Session")]
impl SesionReenviada {
    /// Cerrar de verdad, no sólo dejar de mirar.
    ///
    /// Sin reenviar esto, apretar «dejar de compartir» sacaría la sesión de la
    /// vista del portal y `xdpw` seguiría capturando: la persona creería que
    /// dejó de compartir su pantalla y no sería cierto. Es la peor forma de
    /// fallar que tiene esta pantalla.
    async fn close(&self, #[zbus(connection)] connection: &zbus::Connection) {
        if let Err(error) = connection
            .call_method(Some(WLR_NAME), &self.destino, Some(SESSION_IFACE), "Close", &())
            .await
        {
            eprintln!("[vasak-permissions-agent] no se pudo cerrar la sesión en wlr: {error}");
        }
        let _ = connection.object_server().remove::<Self, _>(&self.destino).await;
    }

    #[zbus(signal)]
    async fn closed(emisor: &zbus::object_server::SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        1
    }
}

/// Lee una propiedad del backend de wlr.
async fn propiedad_de_wlr(nombre: &str) -> Option<u32> {
    let connection = zbus::Connection::session().await.ok()?;
    let reply = connection
        .call_method(
            Some(WLR_NAME),
            WLR_PATH,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(SCREENCAST_IFACE, nombre),
        )
        .await
        .ok()?;
    reply.body().deserialize::<OwnedValue>().ok()?.downcast_ref::<u32>().ok()
}

fn traducir<R: Runtime>(app: &AppHandle<R>, clave: &str) -> String {
    use tauri_plugin_i18n_vsk::PluginI18nExt;
    app.i18n().translate(clave).unwrap_or(clave).to_string()
}

/// El camino de objeto donde el portal espera encontrarnos.
pub const BACKEND_PATH: &str = crate::portal::BACKEND_PATH;

/// Deja constancia de que estos caminos son los que el portal usa, y que un
/// cambio de nombre en `portal.rs` no los puede separar sin que el compilador
/// lo note.
const _: () = {
    assert!(matches!(BACKEND_PATH.as_bytes(), b"/org/freedesktop/portal/desktop"));
    assert!(matches!(WLR_PATH.as_bytes(), b"/org/freedesktop/portal/desktop"));
};

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::object_server::Interface;

    /// La introspección que el portal lee de una interfaz nuestra.
    fn firma<I: Interface>(interfaz: &I) -> String {
        let mut xml = String::new();
        interfaz.introspect_to_writer(&mut xml, 0);
        xml
    }

    /// Los métodos contestan dos valores, no una estructura con dos adentro.
    ///
    /// Escrito como `-> Respuesta` —un alias— zbus lo tomaba por un valor solo
    /// y lo serializaba envuelto: `(ua{sv})` donde la especificación pide
    /// `ua{sv}`. Compila igual, se lee igual, y el portal no puede leer la
    /// respuesta. No hay tipo de Rust que ate esto: la única forma de mirarlo
    /// es la firma que sale por el bus.
    #[test]
    fn los_metodos_contestan_dos_valores_sueltos() {
        let app = tauri::test::mock_app();
        let backend = ScreenCastBackend { app: app.handle().clone() };
        let xml = firma(&backend);

        for metodo in ["CreateSession", "SelectSources", "Start"] {
            let bloque = bloque_del_metodo(&xml, metodo);
            let salidas: Vec<&str> = bloque
                .lines()
                .filter(|l| l.contains(r#"direction="out""#))
                .collect();
            assert_eq!(
                salidas.len(),
                2,
                "{metodo} tiene que sacar dos valores y saca {}:\n{bloque}",
                salidas.len()
            );
            assert!(salidas[0].contains(r#"type="u""#), "{metodo}: {}", salidas[0]);
            assert!(salidas[1].contains(r#"type="a{sv}""#), "{metodo}: {}", salidas[1]);
        }
    }

    /// La propiedad se llama `version`, con minúscula.
    ///
    /// zbus renombra a PascalCase salvo que se le diga el nombre, así que salía
    /// `Version`. El portal lee `version`, no la encontraba, tomaba el backend
    /// por versión 0 y no lo usaba — sin un error en ningún lado: compartir
    /// pantalla simplemente no hacía nada.
    #[test]
    fn la_version_se_anuncia_con_el_nombre_que_el_portal_busca() {
        let app = tauri::test::mock_app();
        let backend = ScreenCastBackend { app: app.handle().clone() };
        let xml = firma(&backend);
        assert!(xml.contains(r#"<property name="version""#), "{xml}");
        assert!(!xml.contains(r#"<property name="Version""#), "{xml}");

        let sesion = SesionReenviada {
            destino: OwnedObjectPath::try_from("/org/freedesktop/portal/desktop/session/1/2")
                .unwrap(),
        };
        let xml = firma(&sesion);
        assert!(xml.contains(r#"<property name="version""#), "{xml}");
        assert!(!xml.contains(r#"<property name="Version""#), "{xml}");
    }

    /// El trozo de XML de un método, del `<method name=…>` a su cierre.
    fn bloque_del_metodo<'a>(xml: &'a str, metodo: &str) -> &'a str {
        let abre = format!(r#"<method name="{metodo}">"#);
        let desde = xml.find(&abre).unwrap_or_else(|| panic!("falta {metodo}:\n{xml}"));
        let hasta = xml[desde..].find("</method>").expect("método sin cerrar") + desde;
        &xml[desde..hasta]
    }

    /// Si `xdg-desktop-portal-wlr` no está en el bus, no hay nada que probar y
    /// eso no es una falla: en una máquina de compilación no corre ninguna
    /// sesión gráfica.
    async fn hay_wlr(connection: &zbus::Connection) -> bool {
        zbus::fdo::DBusProxy::new(connection)
            .await
            .ok()
            .map(|p| async move { p.name_has_owner(WLR_NAME.try_into().unwrap()).await })
            .unwrap()
            .await
            .unwrap_or(false)
    }

    /// Las propiedades se leen del backend de atrás y no se inventan.
    ///
    /// Anunciar una capacidad que wlr no tiene —capturar una ventana suelta,
    /// por ejemplo— haría que una aplicación la pida y falle recién al
    /// intentarlo, cuando ya le dijimos que sí.
    #[tokio::test]
    async fn las_capacidades_salen_de_wlr() {
        let Ok(connection) = zbus::Connection::session().await else {
            return;
        };
        if !hay_wlr(&connection).await {
            return;
        }

        let tipos = propiedad_de_wlr("AvailableSourceTypes").await;
        assert!(tipos.is_some(), "wlr está en el bus y no contestó AvailableSourceTypes");
        // Al menos monitores: un backend de captura que no captura nada sería
        // otro problema, pero no éste.
        assert!(tipos.unwrap() & 1 != 0, "wlr dice que no puede capturar monitores");

        assert!(propiedad_de_wlr("AvailableCursorModes").await.is_some());
    }

    /// El reenvío llega de verdad: se crea una sesión contra el wlr real y se
    /// cierra.
    ///
    /// `CreateSession` no muestra ninguna ventana —las que muestran son
    /// `SelectSources` y `Start`—, así que esto se puede correr sin
    /// interrumpir a nadie.
    #[tokio::test]
    async fn crear_una_sesion_llega_a_wlr() {
        let Ok(connection) = zbus::Connection::session().await else {
            return;
        };
        if !hay_wlr(&connection).await {
            return;
        }

        let pid = std::process::id();
        let handle = format!("/org/freedesktop/portal/desktop/request/prueba{pid}");
        let sesion = format!("/org/freedesktop/portal/desktop/session/prueba{pid}");
        let handle = OwnedObjectPath::try_from(handle).unwrap();
        let sesion = OwnedObjectPath::try_from(sesion).unwrap();

        let (codigo, _) = reenviar(
            &connection,
            "CreateSession",
            &(&handle, &sesion, "ar.net.vasak.prueba", HashMap::<String, OwnedValue>::new()),
        )
        .await;

        assert_eq!(codigo, RESPONSE_GRANTED, "wlr no aceptó crear la sesión");

        // Y se cierra, para no dejarle una sesión colgada.
        let _ = connection
            .call_method(Some(WLR_NAME), &sesion, Some(SESSION_IFACE), "Close", &())
            .await;
    }

    /// Cancelar y fallar no son lo mismo, y confundirlos manda a quien depure
    /// esto al lugar equivocado: «cancelado» significa que la persona dijo que
    /// no.
    #[test]
    fn cancelado_y_error_son_codigos_distintos() {
        assert_ne!(RESPONSE_CANCELLED, RESPONSE_ERROR);
        assert_eq!(RESPONSE_GRANTED, 0);
    }

    /// El backend y wlr atienden en el mismo camino de objeto, cada uno en su
    /// conexión. Si dejaran de coincidir, el reenvío iría a un objeto que no
    /// existe y toda captura fallaría.
    #[test]
    fn el_camino_de_objeto_es_el_mismo_de_los_dos_lados() {
        assert_eq!(BACKEND_PATH, WLR_PATH);
    }
}
