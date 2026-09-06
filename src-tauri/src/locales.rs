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

    /// Que los dos catálogos digan lo mismo, y que se puedan leer.
    ///
    /// Sin esto, un YAML roto se envía callado: la aplicación abre igual y
    /// muestra la clave cruda donde iba el texto. Pasó al escribir estos
    /// mismos textos — una etiqueta en inglés con apóstrofo dentro de comillas
    /// simples («'Don't allow'») deja el archivo inválido desde esa línea hacia
    /// abajo, y nada lo decía.
    ///
    /// La comprobación es por líneas y no con un analizador de YAML: agregar
    /// una dependencia para leer dos archivos en una prueba es más de lo que
    /// hace falta, y lo que importa —que las claves coincidan y que no haya
    /// comillas mal cerradas— se ve así.
    #[test]
    fn los_dos_catalogos_tienen_las_mismas_claves() {
        let claves_de = |texto: &str| -> std::collections::BTreeSet<String> {
            let mut claves = std::collections::BTreeSet::new();
            let mut pila: Vec<String> = Vec::new();
            let mut sangria_del_bloque: Option<usize> = None;

            for linea in texto.lines() {
                if linea.trim().is_empty() || linea.trim_start().starts_with('#') {
                    continue;
                }
                let sangria = linea.len() - linea.trim_start().len();

                // Adentro de un bloque `>-` o `|` todo es texto, no YAML: una
                // línea de prosa que empiece con «palabra:» no es una clave.
                if let Some(nivel) = sangria_del_bloque {
                    if sangria > nivel {
                        continue;
                    }
                    sangria_del_bloque = None;
                }

                let Some((clave, valor)) = linea.trim().split_once(':') else {
                    continue;
                };
                if clave.contains(' ') || clave.is_empty() {
                    continue;
                }
                pila.truncate(sangria / 2);
                pila.push(clave.trim_matches(['"', '\'']).to_string());

                let valor = valor.trim();
                if !valor.is_empty() {
                    claves.insert(pila.join("."));
                }
                if valor.starts_with('>') || valor.starts_with('|') {
                    sangria_del_bloque = Some(sangria);
                }
            }
            claves
        };

        let raiz = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("locales");
        let es = claves_de(&std::fs::read_to_string(raiz.join("es.yml")).unwrap());
        let en = claves_de(&std::fs::read_to_string(raiz.join("en.yml")).unwrap());

        let solo_es: Vec<_> = es.difference(&en).collect();
        let solo_en: Vec<_> = en.difference(&es).collect();
        assert!(
            solo_es.is_empty() && solo_en.is_empty(),
            "sólo en español: {solo_es:?}; sólo en inglés: {solo_en:?}"
        );
        assert!(es.len() > 20, "se leyeron {} claves: el lector no anda", es.len());
    }

    /// Y que ninguna cadena entrecomillada esté mal escrita.
    ///
    /// Es lo que rompe el archivo entero desde esa línea para abajo, y sin
    /// analizador de YAML no se nota. Pasó al escribir estos mismos textos:
    /// `'Don't allow'` **parece** bien —abre y cierra con comilla— pero en YAML
    /// una comilla simple adentro de una cadena entrecomillada con simples
    /// tiene que ir duplicada (`'Don''t allow'`). Una primera versión de esta
    /// prueba sólo miraba que abriera y cerrara, así que dejaba pasar
    /// exactamente el error que existía para detectar.
    #[test]
    fn ninguna_cadena_entrecomillada_esta_mal_escrita() {
        let raiz = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("locales");
        for idioma in SOPORTADOS {
            let texto = std::fs::read_to_string(raiz.join(format!("{idioma}.yml"))).unwrap();
            for (n, linea) in texto.lines().enumerate() {
                let Some((_, valor)) = linea.trim().split_once(':') else {
                    continue;
                };
                let valor = valor.trim();
                let Some(resto) = valor.strip_prefix('\'') else {
                    continue;
                };
                let sitio = format!("{idioma}.yml:{}", n + 1);
                let interior = resto
                    .strip_suffix('\'')
                    .unwrap_or_else(|| panic!("{sitio}: la comilla no cierra: {valor}"));

                // Adentro, las comillas simples van de a pares. Una suelta
                // termina la cadena antes de tiempo.
                let mut sueltas = 0;
                let mut corrida = 0;
                for c in interior.chars() {
                    if c == '\'' {
                        corrida += 1;
                    } else {
                        if corrida % 2 != 0 {
                            sueltas += 1;
                        }
                        corrida = 0;
                    }
                }
                if corrida % 2 != 0 {
                    sueltas += 1;
                }
                assert_eq!(
                    sueltas, 0,
                    "{sitio}: hay una comilla simple sin duplicar, que corta la cadena: {valor}"
                );
            }
        }
    }

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
