//! Un `AppHandle` que todavía no existe.
//!
//! # Por qué hace falta
//!
//! El backend del portal tiene que tomar su nombre de bus **antes** de que
//! Tauri construya la aplicación. Construirla inicializa GTK, y `GtkApplication`
//! sondea el gestor de sesión al registrarse, lo que activa
//! `xdg-desktop-portal` y bloquea hasta que conteste; el portal, a su vez, no
//! termina de arrancar hasta encontrar el backend de
//! `org.freedesktop.impl.portal.Access`, que es justamente este proceso. Cuando
//! el nombre se tomaba después —en `setup()`, que corre adentro de `build()`—
//! los dos se esperaban quince segundos, hasta que systemd mataba al portal por
//! plazo vencido, y esos quince segundos los pagaba toda aplicación GTK que
//! arrancara en ese rato, el escritorio incluido.
//!
//! O sea que en el momento de publicar los backends no hay ningún manejador que
//! meterles adentro. Esto es el hueco donde va a entrar, y la espera de quien lo
//! necesite antes de tiempo.
//!
//! # Por qué esperar no cuelga
//!
//! Ningún método del portal se invoca hasta que alguien pide un permiso, y para
//! entonces la aplicación hace rato que existe. Si aun así llegara un pedido en
//! esa ventana, `esperar` se duerme hasta que el manejador aparezca — y si la
//! aplicación nunca llega a construirse, el otro extremo se suelta y la espera
//! corta con `None` en vez de quedarse para siempre.

use tauri::{AppHandle, Runtime};
use tokio::sync::watch;

/// El hueco, del lado de quien va a leerlo.
pub struct MasTarde<R: Runtime = tauri::Wry> {
    receptor: watch::Receiver<Option<AppHandle<R>>>,
}

/// La punta que lo llena, del lado de quien construye la aplicación.
///
/// Llenarlo la consume: el manejador se pone una vez y no cambia.
pub struct Cuando<R: Runtime = tauri::Wry> {
    emisor: watch::Sender<Option<AppHandle<R>>>,
}

/// Abre un hueco vacío y devuelve sus dos puntas.
pub fn hueco<R: Runtime>() -> (Cuando<R>, MasTarde<R>) {
    let (emisor, receptor) = watch::channel(None);
    (Cuando { emisor }, MasTarde { receptor })
}

impl<R: Runtime> Cuando<R> {
    /// Deja el manejador a la vista de todo el que esté esperando.
    pub fn llenar(self, app: AppHandle<R>) {
        // Se descarta el error a propósito: significa que nadie quedó
        // escuchando, que es exactamente el caso en que no hay nada que hacer.
        let _ = self.emisor.send(Some(app));
    }
}

impl<R: Runtime> MasTarde<R> {
    /// Espera a que la aplicación exista.
    ///
    /// Devuelve `None` sólo si la aplicación no va a existir nunca, que es
    /// cuando la otra punta se suelta sin haberse llenado.
    pub async fn esperar(&self) -> Option<AppHandle<R>> {
        let mut receptor = self.receptor.clone();
        loop {
            // El clon sale del `borrow` en la misma sentencia: sostener la
            // guarda a través del `await` de abajo trabaría a quien llena.
            let actual = receptor.borrow().clone();
            if actual.is_some() {
                return actual;
            }
            receptor.changed().await.ok()?;
        }
    }
}

impl<R: Runtime> Clone for MasTarde<R> {
    /// A mano y no derivado: `derive(Clone)` pediría `R: Clone`, que no hace
    /// falta —lo que se clona es el receptor, no el runtime.
    fn clone(&self) -> Self {
        Self {
            receptor: self.receptor.clone(),
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// La propiedad que hace posible invertir el orden: se puede pedir el
    /// manejador antes de que exista, y la espera termina cuando aparece.
    ///
    /// Sin esto habría que volver a publicar el backend recién con la
    /// aplicación armada, que es exactamente lo que trababa el inicio de sesión
    /// quince segundos.
    #[tokio::test]
    async fn el_manejador_llega_aunque_se_lo_pida_antes_de_que_exista() {
        let (cuando, mas_tarde) = hueco::<tauri::test::MockRuntime>();

        let esperando = tokio::spawn(async move { mas_tarde.esperar().await.is_some() });

        // Se llena después de que el otro lado ya está esperando.
        let app = tauri::test::mock_app();
        cuando.llenar(app.handle().clone());

        assert!(
            esperando
                .await
                .expect("la espera no debería entrar en pánico"),
            "quien pidió el manejador antes de tiempo se quedó sin él"
        );
    }

    /// El techo de la espera. Si la aplicación no llega a construirse, la otra
    /// punta se suelta y quien esperaba tiene que enterarse en vez de quedarse
    /// colgado para siempre — que en un backend de portal significa un pedido
    /// que nunca contesta y un `xdg-desktop-portal` esperándolo.
    #[tokio::test]
    async fn si_la_aplicacion_no_llega_a_existir_la_espera_corta() {
        let (cuando, mas_tarde) = hueco::<tauri::test::MockRuntime>();
        drop(cuando);

        assert!(
            mas_tarde.esperar().await.is_none(),
            "la espera tendría que haber cortado al soltarse la otra punta"
        );
    }

    /// El caso normal, que es el que corre siempre: para cuando llega un pedido
    /// de verdad el hueco hace rato que está lleno, y leerlo no espera nada.
    #[tokio::test]
    async fn un_hueco_ya_lleno_se_lee_sin_esperar() {
        let (cuando, mas_tarde) = hueco::<tauri::test::MockRuntime>();
        let app = tauri::test::mock_app();
        cuando.llenar(app.handle().clone());

        assert!(mas_tarde.esperar().await.is_some());
    }

    /// Los dos backends viven en el mismo nombre de bus y cada uno se queda con
    /// una copia, así que clonar el hueco tiene que seguir mirando el mismo
    /// manejador. Con una copia que se quedara vacía, uno de los dos backends
    /// no podría preguntar nunca.
    #[tokio::test]
    async fn las_copias_del_hueco_ven_el_mismo_manejador() {
        let (cuando, mas_tarde) = hueco::<tauri::test::MockRuntime>();
        let copia = mas_tarde.clone();

        let app = tauri::test::mock_app();
        cuando.llenar(app.handle().clone());

        assert!(mas_tarde.esperar().await.is_some());
        assert!(copia.esperar().await.is_some(), "la copia se quedó vacía");
    }
}
