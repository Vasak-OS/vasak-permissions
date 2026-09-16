//! The desktop portal's permission dialog.
//!
//! `xdg-desktop-portal` handles a program's request for the camera, the
//! location, running in the background and so on, and asks a *backend* to put
//! the question to the person. Implementing that backend is what makes those
//! dialogs look like the rest of VasakOS instead of borrowing GNOME's.
//!
//! # Lo que se guarda, y contra qué
//!
//! La respuesta se anota en el servicio de permisos, contra el `app_id` que el
//! portal entrega. Antes no se anotaba en ningún lado y el diálogo volvía a
//! aparecer cada vez; `politica` cuenta el caso medido y por qué eso era peor
//! que guardar una identidad imperfecta.
//!
//! Este comentario decía que el `app_id` «está vacío para cualquier cosa fuera
//! de un sandbox», y sobre eso apoyaba la decisión de no guardar nada. Dejó de
//! ser cierto: `xdg-desktop-portal` 1.22 expone
//! `org.freedesktop.host.portal.Registry`, donde una aplicación sin sandbox
//! declara su identificador, y las basadas en Chromium la usan — lo que llega
//! es `com.google.Chrome`. Vacío llega sólo lo que no se registra, y eso se
//! sigue preguntando cada vez.
//!
//! Lo que **no** cambió es cuánto vale esa identidad: la declara la propia
//! aplicación y no la comprueba nadie. Por eso estas entradas quedan como
//! `Provenance::Unverified` y el diálogo sigue sin presentarlas como un
//! programa identificado — que es otra cosa que un programa que dijo su nombre.

use zbus::interface;
use zbus::zvariant::{ObjectPath, OwnedValue};

use crate::dialog::{PortalQuestion, Question};
use crate::mas_tarde::MasTarde;

/// The name a portal backend is found under. It has to match the `.portal`
/// file installed alongside, or the portal never looks here.
pub const BACKEND_NAME: &str = "org.freedesktop.impl.portal.desktop.vasak";
pub const BACKEND_PATH: &str = "/org/freedesktop/portal/desktop";

/// Response codes from the portal specification.
const RESPONSE_GRANTED: u32 = 0;
const RESPONSE_CANCELLED: u32 = 1;
/// «Falló», que no es lo mismo que «dijo que no»: decir que la persona
/// rechazó algo que en realidad nunca se le llegó a preguntar manda a quien
/// depure esto a buscar en el lugar equivocado.
const RESPONSE_ERROR: u32 = 2;

pub struct AccessBackend {
    /// La aplicación, que al publicar este backend todavía no existe.
    /// Ver `crate::mas_tarde`.
    pub app: MasTarde,
}

#[interface(name = "org.freedesktop.impl.portal.Access")]
impl AccessBackend {
    /// Puts the portal's question to the person.
    ///
    /// The reply is `(response, results)`. Nothing is returned in `results`:
    /// that carries the answers to the extra `choices` a caller may attach, and
    /// this dialog deliberately offers only allow and refuse — a permission
    /// prompt that also asks three side questions is one people stop reading.
    #[allow(clippy::too_many_arguments)]
    async fn access_dialog(
        &self,
        handle: ObjectPath<'_>,
        app_id: String,
        parent_window: String,
        title: String,
        subtitle: String,
        body: String,
        options: std::collections::HashMap<String, OwnedValue>,
    ) -> (u32, std::collections::HashMap<String, OwnedValue>) {
        // Named without underscores because the names travel: they appear in the
        // introspection the portal and anyone debugging it reads.
        //
        // `handle` would let the portal cancel a request; this dialog answers
        // quickly and closes itself, so there is nothing to cancel. The parent
        // window cannot be honoured either — Wayland gives a client no way to
        // place itself over another client's window.
        let _ = (handle, parent_window);

        let Some(app) = self.app.esperar().await else {
            // La aplicación no llegó a construirse, así que no hay con qué
            // preguntar. No se concede: el permiso que nadie pudo autorizar no
            // es un permiso otorgado.
            eprintln!(
                "[vasak-permissions-agent] llegó un pedido de permiso y la aplicación no existe"
            );
            return (RESPONSE_ERROR, std::collections::HashMap::new());
        };

        // Qué recurso es, si se puede saber. Esta interfaz es genérica —la
        // misma atiende la cámara, la ubicación y correr en segundo plano— y no
        // lo dice; `recurso_del_dialogo` lo deduce de lo poco que hay, y
        // devuelve `None` cuando no puede. Sin recurso no se guarda nada y se
        // pregunta cada vez, que es lo que pasaba siempre.
        let recurso = crate::politica::recurso_del_dialogo(&options);

        let granted = crate::politica::decidir(
            &app,
            &app_id,
            recurso,
            Question::Portal(PortalQuestion {
                app_id: app_id.clone(),
                title,
                subtitle,
                body,
            }),
        )
        .await;

        let response = if granted {
            RESPONSE_GRANTED
        } else {
            // Cancelled rather than a distinct "denied": the portal treats
            // anything other than success as not granted, and this is the code
            // it expects for a person who said no.
            RESPONSE_CANCELLED
        };

        (response, std::collections::HashMap::new())
    }

    /// Advertised so the portal knows what it is talking to. The portal checks
    /// this before using a backend.
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        1
    }
}

/// Claims the backend name on the session bus.
///
/// Separate from the connection the agent uses to reach the permission service:
/// that one is the *system* bus, and the portal only ever looks on the session
/// bus. One process, two buses, because the two jobs live in different places.
pub async fn serve(app: MasTarde) -> Result<zbus::Connection, String> {
    // Un solo registro para las tres piezas: el backend lo llena al empezar
    // una captura, la sesión lo vacía al cerrarse, y el servicio lo lee. Es un
    // `Arc` adentro, así que las copias son el mismo registro.
    let capturas = crate::capturas::Registro::nuevo();

    zbus::connection::Builder::session()
        .map_err(|e| format!("no se pudo abrir el bus de sesión: {e}"))?
        .name(BACKEND_NAME)
        .map_err(|e| format!("no se pudo tomar el nombre {BACKEND_NAME}: {e}"))?
        .serve_at(BACKEND_PATH, AccessBackend { app: app.clone() })
        .map_err(|e| format!("no se pudo publicar el backend del portal: {e}"))?
        // La captura de pantalla, en el mismo nombre y el mismo camino: el
        // portal busca todas las interfaces de un backend ahí.
        .serve_at(
            BACKEND_PATH,
            crate::portal_screencast::ScreenCastBackend {
                app,
                capturas: capturas.clone(),
            },
        )
        .map_err(|e| format!("no se pudo publicar el backend de captura: {e}"))?
        // Y aparte, en su propio camino, lo que el panel consulta: qué se está
        // capturando ahora mismo. No va en `BACKEND_PATH` a propósito — ahí
        // viven las interfaces que el portal espera encontrar, y esta no es
        // una de ellas.
        .serve_at(
            crate::capturas::RUTA,
            crate::capturas::ServicioDeCapturas {
                registro: capturas,
                wlr: crate::portal_screencast::WLR_NAME,
            },
        )
        .map_err(|e| format!("no se pudo publicar el servicio de capturas: {e}"))?
        .build()
        .await
        .map_err(|e| format!("no se pudo conectar al bus de sesión: {e}"))
}
