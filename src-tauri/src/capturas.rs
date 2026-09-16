//! Qué se está capturando ahora mismo, y poder cortarlo.
//!
//! El diálogo de captura promete un indicador en la barra —«podés dejar de
//! compartir en cualquier momento desde el indicador»— y ese indicador no
//! existía porque no había forma de preguntarle al agente qué sesiones tiene
//! vivas. El agente **sí** las conoce: exporta una por cada captura en curso y
//! sabe cerrarlas. Lo que faltaba era decirlo hacia afuera.
//!
//! Esto es ese lado: un registro de lo que está vivo, y una interfaz para
//! consultarlo, escuchar cuando cambia, y cortar una.
//!
//! Se registra en `Start` y no en `SelectSources`: conceder no es capturar.
//! Entre una cosa y la otra `xdpw` todavía muestra su selector de monitor, y
//! anunciar ahí que te están mirando sería mentir en el sentido más caro — el
//! que enseña a no creerle al indicador.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;

/// Dónde vive la interfaz.
pub const RUTA: &str = "/ar/net/vasak/os/Captura";

/// Cómo se llama.
///
/// El macro de la interfaz no acepta una constante, así que el nombre queda
/// escrito dos veces y hay un test que comprueba que digan lo mismo. Fuera de
/// ese test nadie la usa desde acá: quien la consume es el panel, que es otro
/// proceso. De ahí el permiso.
#[allow(dead_code)]
pub const INTERFAZ: &str = "ar.net.vasak.os.Captura";

/// Lo que está capturando ahora mismo, indexado por la sesión del portal.
///
/// El identificador de sesión es del portal y no nuestro a propósito: es el
/// mismo que hay que mandarle de vuelta para cerrarla, así que quien lea la
/// lista puede cortar sin que haga falta traducir nada en el medio.
#[derive(Clone, Default)]
pub struct Registro {
    vivas: Arc<Mutex<BTreeMap<String, String>>>,
}

impl Registro {
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Anota una captura que acaba de empezar.
    pub async fn sumar(&self, sesion: &OwnedObjectPath, app_id: &str) {
        self.vivas
            .lock()
            .await
            .insert(sesion.as_str().to_string(), app_id.to_string());
    }

    /// Saca una que terminó. Devuelve si había algo que sacar.
    pub async fn sacar(&self, sesion: &OwnedObjectPath) -> bool {
        self.vivas.lock().await.remove(sesion.as_str()).is_some()
    }

    /// Lo que está vivo, como pares (sesión, aplicación).
    pub async fn vivas(&self) -> Vec<(String, String)> {
        self.vivas
            .lock()
            .await
            .iter()
            .map(|(sesion, app)| (sesion.clone(), app.clone()))
            .collect()
    }
}

/// Avisa que la lista cambió.
///
/// Se emite desde donde pasó el cambio y no desde el registro: el registro no
/// tiene conexión, y dársela para esto lo ataría a D-Bus sin necesidad — se
/// prueba mejor sin.
pub async fn avisar(connection: &zbus::Connection) {
    let Ok(emisor) = SignalEmitter::new(connection, RUTA) else {
        return;
    };
    if let Err(error) = ServicioDeCapturas::cambiaron(&emisor).await {
        eprintln!("[vasak-permissions-agent] no se pudo avisar del cambio de capturas: {error}");
    }
}

/// La interfaz que consulta el panel.
pub struct ServicioDeCapturas {
    pub registro: Registro,
    /// A quién se le pide el cierre de verdad.
    pub wlr: &'static str,
}

#[interface(name = "ar.net.vasak.os.Captura")]
impl ServicioDeCapturas {
    /// Qué se está capturando: pares de (sesión, identificador de aplicación).
    ///
    /// Se consulta además de escuchar la señal porque el panel se destruye y se
    /// vuelve a crear —al cambiar de monitor, por ejemplo— y el nuevo nace sin
    /// saber nada.
    async fn sesiones(&self) -> Vec<(String, String)> {
        self.registro.vivas().await
    }

    /// Corta una captura en curso.
    ///
    /// Reenvía `Close` a `xdpw`, que es lo único que la detiene de verdad.
    /// Sacarla nada más de nuestra lista dejaría a alguien creyendo que dejó de
    /// compartir su pantalla sin que fuera cierto, que es la peor forma de
    /// fallar que tiene esto.
    async fn cerrar(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        sesion: String,
    ) -> zbus::fdo::Result<()> {
        let ruta = OwnedObjectPath::try_from(sesion.as_str())
            .map_err(|error| zbus::fdo::Error::InvalidArgs(format!("sesión inválida: {error}")))?;

        connection
            .call_method(
                Some(self.wlr),
                &ruta,
                Some("org.freedesktop.impl.portal.Session"),
                "Close",
                &(),
            )
            .await
            .map_err(|error| {
                zbus::fdo::Error::Failed(format!("no se pudo cerrar la sesión: {error}"))
            })?;

        if self.registro.sacar(&ruta).await {
            avisar(connection).await;
        }
        Ok(())
    }

    /// La lista cambió: alguien empezó o dejó de capturar.
    #[zbus(signal)]
    async fn cambiaron(emisor: &SignalEmitter<'_>) -> zbus::Result<()>;
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ruta(texto: &str) -> OwnedObjectPath {
        OwnedObjectPath::try_from(texto).expect("ruta de prueba inválida")
    }

    #[tokio::test]
    async fn arranca_vacio() {
        assert!(Registro::nuevo().vivas().await.is_empty());
    }

    #[tokio::test]
    async fn anota_y_saca() {
        let registro = Registro::nuevo();
        let sesion = ruta("/org/freedesktop/portal/desktop/session/1_1/x");

        registro.sumar(&sesion, "com.google.Chrome").await;
        assert_eq!(
            registro.vivas().await,
            vec![(sesion.as_str().to_string(), "com.google.Chrome".to_string())]
        );

        assert!(
            registro.sacar(&sesion).await,
            "estaba, tiene que salir true"
        );
        assert!(registro.vivas().await.is_empty());
    }

    /// Cerrar dos veces la misma sesión no puede avisar dos veces: el aviso
    /// cuelga de que hubiera algo que sacar.
    #[tokio::test]
    async fn sacar_lo_que_no_esta_no_miente() {
        let registro = Registro::nuevo();
        assert!(!registro.sacar(&ruta("/no/existe")).await);
    }

    /// Dos aplicaciones capturando a la vez es el caso que el indicador tiene
    /// que mostrar entero, no sólo la primera.
    #[tokio::test]
    async fn conviven_varias() {
        let registro = Registro::nuevo();
        registro
            .sumar(&ruta("/sesion/1"), "org.mozilla.firefox")
            .await;
        registro
            .sumar(&ruta("/sesion/2"), "com.obsproject.Studio")
            .await;

        let vivas = registro.vivas().await;
        assert_eq!(vivas.len(), 2);
        assert!(vivas.iter().any(|(_, app)| app == "org.mozilla.firefox"));
        assert!(vivas.iter().any(|(_, app)| app == "com.obsproject.Studio"));
    }

    /// El nombre de la interfaz está escrito dos veces —en la constante y en
    /// el atributo del macro— porque el macro no acepta una constante. Si se
    /// separan, el panel pregunta en un nombre que nadie atiende y el
    /// indicador no aparece nunca, sin un error en ningún lado.
    #[test]
    fn el_nombre_declarado_es_el_que_se_publica() {
        let fuente = include_str!("capturas.rs");
        assert!(
            fuente.contains(&format!("#[interface(name = \"{INTERFAZ}\")]")),
            "la constante dice «{INTERFAZ}» y el atributo dice otra cosa"
        );
    }

    /// Lo mismo con el camino: lo usa quien publica la interfaz y quien emite
    /// la señal, y tienen que ser el mismo.
    #[test]
    fn la_ruta_es_una_ruta_de_objeto_valida() {
        assert!(
            OwnedObjectPath::try_from(RUTA).is_ok(),
            "«{RUTA}» no es un camino de objeto que D-Bus acepte"
        );
    }

    /// El registro se clona por valor y tiene que seguir siendo el mismo: el
    /// backend del portal, la sesión y el servicio tienen cada uno su copia.
    #[tokio::test]
    async fn el_clon_es_el_mismo_registro() {
        let registro = Registro::nuevo();
        let copia = registro.clone();

        copia.sumar(&ruta("/sesion/1"), "app").await;
        assert_eq!(
            registro.vivas().await.len(),
            1,
            "la copia anotó en otro lado"
        );
    }
}
