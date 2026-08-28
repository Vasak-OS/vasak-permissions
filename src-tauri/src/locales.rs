//! Dónde están los catálogos de idioma y cuál usar.
//!
//! Separado del arranque porque es la parte que se rompe callado: si la ruta no
//! se resuelve, la aplicación abre igual y muestra las claves crudas en lugar
//! de los textos. Pasó en el gestor de archivos, en la terminal y en la galería.

use std::path::PathBuf;

/// El nombre del paquete, que también es el directorio bajo `/usr/share`.
/// El directorio bajo `/usr/share`, que es el nombre del paquete.
const NOMBRE: &str = "vasak-permissions";

/// Los idiomas que la aplicación trae traducidos.
///
/// Cualquier otro cae en el de reserva: es mejor mostrar todo en un idioma que
/// una mezcla con claves crudas donde falte una traducción.
const SOPORTADOS: &[&str] = &["es", "en"];

/// El de reserva. Español, que es el idioma por omisión del sistema.
const RESERVA: &str = "es";

/// Dónde buscar los `.yml`, en orden.
///
/// Las dos primeras son para desarrollo —según desde dónde se ejecute— y la
/// tercera es la única que existe cuando la aplicación está instalada.
pub fn directorio() -> Option<String> {
    [
        PathBuf::from("locales"),
        PathBuf::from("src-tauri/locales"),
        PathBuf::from(format!("/usr/share/{NOMBRE}/locales")),
    ]
    .into_iter()
    .find(|ruta| ruta.is_dir())
    .map(|ruta| ruta.to_string_lossy().to_string())
}

/// El idioma de la sesión, o el de reserva.
///
/// Se recorren las tres variables en el orden de precedencia de POSIX, y se
/// **saltean las vacías**: `LC_ALL=""` junto a `LANG=en_US.UTF-8` es una máquina
/// en inglés, y quedarse con la vacía la dejaría en español.
pub fn idioma_del_sistema() -> String {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .filter_map(|nombre| std::env::var(nombre).ok())
        .find(|valor| !valor.trim().is_empty())
        .and_then(|valor| codigo_de_idioma(&valor))
        .unwrap_or_else(|| RESERVA.to_string())
}

/// Saca el código de idioma de un valor de locale: `es_AR.UTF-8@euro` -> `es`.
fn codigo_de_idioma(locale: &str) -> Option<String> {
    let codigo = locale.split(['_', '.', '@']).next()?;
    if codigo.is_empty() {
        return None;
    }
    SOPORTADOS
        .contains(&codigo)
        .then(|| codigo.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn se_saca_el_idioma_de_un_locale_completo() {
        assert_eq!(codigo_de_idioma("es_AR.UTF-8"), Some("es".to_string()));
        assert_eq!(codigo_de_idioma("en_US.UTF-8@euro"), Some("en".to_string()));
        assert_eq!(codigo_de_idioma("es"), Some("es".to_string()));
    }

    #[test]
    fn un_idioma_sin_traducir_no_se_acepta() {
        // Mejor todo en el idioma de reserva que una mezcla con claves crudas
        // donde falte una traducción.
        assert_eq!(codigo_de_idioma("fr_FR.UTF-8"), None);
        assert_eq!(codigo_de_idioma("de"), None);
    }

    #[test]
    fn un_locale_vacio_o_raro_no_da_idioma() {
        assert_eq!(codigo_de_idioma(""), None);
        assert_eq!(codigo_de_idioma("_AR"), None);
        assert_eq!(codigo_de_idioma(".UTF-8"), None);
    }

    #[test]
    fn el_idioma_de_reserva_esta_entre_los_soportados() {
        // Si no, la aplicación caería a un catálogo que no existe.
        assert!(SOPORTADOS.contains(&RESERVA));
    }

    #[test]
    fn los_soportados_no_estan_vacios() {
        assert!(!SOPORTADOS.is_empty());
        for idioma in SOPORTADOS {
            assert!(!idioma.is_empty());
            assert_eq!(idioma.len(), 2, "se esperan códigos de dos letras");
        }
    }
}
