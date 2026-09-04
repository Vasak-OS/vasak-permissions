//! Perfiles de excepción: permitirle a **una** aplicación lo que el perfil
//! general le niega a todas.
//!
//! # Por qué hace falta un perfil aparte
//!
//! El perfil general se engancha a `@{HOME}/**/*.AppImage`, o sea a todos los
//! AppImage a la vez. No hay forma de exceptuar uno tocando ese archivo:
//! cualquier permiso que se agregue ahí se lo lleva el conjunto entero.
//!
//! La salida es un segundo perfil enganchado a la **ruta exacta** de esa
//! aplicación y sin las negaciones. AppArmor elige la coincidencia más
//! específica, así que ésa queda libre y el resto sigue bloqueado.
//!
//! Comprobado a mano antes de escribir esto, con dos aplicaciones de prueba: la
//! que tiene excepción abre la cámara y la otra sigue sin poder.
//!
//! # Lo que este módulo cuida
//!
//! La parte riesgosa no es generar el texto sino **representar la ruta**. La
//! cadena de enganche de AppArmor admite comodines: una ruta que contenga `*`,
//! `?`, `[` o `{` no se interpreta literalmente, y una excepción pensada para
//! una aplicación podría terminar cubriendo otras. Que es justo lo contrario de
//! lo que se pide.
//!
//! Por eso las rutas que no se pueden representar sin ambigüedad **se
//! rechazan** en lugar de intentar escaparlas. Una aplicación en una ruta así
//! se queda sin excepción, y eso es mucho mejor que una excepción que cubra de
//! más sin que nadie se entere.

// Todavía no lo llama nadie, y es a propósito: esto se escribió y se validó
// aparte —el mecanismo se comprobó a mano con dos aplicaciones de prueba— antes
// de conectarlo a un botón. Decidir *cuándo* se concede una excepción tiene
// preguntas abiertas: si vale para siempre o por una vez, y qué pasa cuando la
// aplicación se actualiza y la ruta ya no contiene el mismo binario.
//
// Este `allow` se saca en cuanto exista quien lo llame.
#![allow(dead_code)]

/// Por qué una ruta no puede tener excepción.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Motivo {
    /// Sin ruta absoluta no hay enganche posible.
    NoEsAbsoluta,
    /// Lleva un carácter que AppArmor leería como comodín, o que rompería la
    /// sintaxis del archivo.
    CaracterAmbiguo(char),
}

impl std::fmt::Display for Motivo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Motivo::NoEsAbsoluta => write!(f, "la ruta no es absoluta"),
            Motivo::CaracterAmbiguo(c) => write!(
                f,
                "la ruta lleva '{c}', que AppArmor podría interpretar como comodín"
            ),
        }
    }
}

/// Los caracteres que no se aceptan en la ruta de una excepción.
///
/// Los cuatro primeros son comodines de AppArmor; los demás romperían la
/// sintaxis del archivo o el entrecomillado.
const AMBIGUOS: &[char] = &['*', '?', '[', ']', '{', '}', '"', '\\', '\n', '\r'];

/// El nombre del perfil para esa ruta.
///
/// Tiene que ser único entre todos los perfiles cargados, así que se deriva de
/// la ruta entera y no del nombre del archivo: dos aplicaciones distintas
/// pueden llamarse igual en carpetas distintas.
///
/// La codificación es reversible —cada `_` de la ruta original se duplica—, así
/// que dos rutas distintas nunca dan el mismo nombre. Sin eso, `/a/b` y `/a_b`
/// colisionarían y una excepción pisaría a la otra.
pub fn nombre_de(ruta: &str) -> String {
    let mut nombre = String::from("vasak-permitida");
    for c in ruta.chars() {
        match c {
            '_' => nombre.push_str("__"),
            '/' => nombre.push('_'),
            c if c.is_ascii_alphanumeric() || c == '-' || c == '.' => nombre.push(c),
            _ => {
                // Cualquier otra cosa —espacios, acentos— va como su código,
                // entre guiones, para no perder la unicidad.
                nombre.push_str(&format!("-{}-", c as u32));
            }
        }
    }
    nombre
}

/// El texto del perfil de excepción para esa ruta.
///
/// Permite todo y no niega nada: es el perfil general menos las negaciones. No
/// se deja "sin perfil" a secas porque entonces ganaría el general, que es el
/// que bloquea.
pub fn perfil_para(ruta: &str) -> Result<String, Motivo> {
    if !ruta.starts_with('/') {
        return Err(Motivo::NoEsAbsoluta);
    }
    if let Some(c) = ruta.chars().find(|c| AMBIGUOS.contains(c)) {
        return Err(Motivo::CaracterAmbiguo(c));
    }

    Ok(format!(
        r#"# ARCHIVO GENERADO — no editar a mano.
#
# Excepción para una aplicación: le devuelve el acceso que el perfil general
# /etc/apparmor.d/vasak-appimage le niega a todas.
#
# Existe porque ese perfil se engancha a todos los AppImage a la vez y no se
# puede exceptuar uno desde ahí. AppArmor elige la coincidencia más específica,
# así que este perfil —enganchado a una ruta exacta— le gana al general.
#
# Se borra para volver a bloquear la aplicación.

abi <abi/4.0>,

include <tunables/global>

profile {nombre} "{ruta}" {{
  # Todo permitido y nada negado: es el perfil general menos las negaciones.
  file,
  network,
  unix,
  signal,
  ptrace,
  dbus,
  capability,
  mount,
  umount,
  pivot_root,
  change_profile,
  io_uring,
  mqueue,
  userns,

  include if exists <local/{nombre}>
}}
"#,
        nombre = nombre_de(ruta),
        ruta = ruta
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_perfil_engancha_la_ruta_exacta_y_no_niega_nada() {
        let perfil = perfil_para("/home/alguien/Apps/cosa.AppImage").unwrap();
        assert!(perfil.contains(r#""/home/alguien/Apps/cosa.AppImage""#));
        assert!(!perfil.contains("deny"), "una excepción no puede negar nada");
        assert!(perfil.contains("file,"));
    }

    /// El caso real: el AppImage del equipo de pruebas tiene espacios.
    #[test]
    fn una_ruta_con_espacios_se_acepta_y_queda_entre_comillas() {
        let perfil = perfil_para("/home/pato/Apps/App Monitor_0.1.0.AppImage").unwrap();
        assert!(perfil.contains(r#""/home/pato/Apps/App Monitor_0.1.0.AppImage""#));
    }

    /// Lo importante de todo el módulo. Una ruta con comodines produciría una
    /// excepción que cubre aplicaciones que nadie autorizó.
    #[test]
    fn las_rutas_con_comodines_se_rechazan() {
        for ruta in [
            "/home/x/todo*.AppImage",
            "/home/x/cosa?.AppImage",
            "/home/x/[ab].AppImage",
            "/home/x/{a,b}.AppImage",
        ] {
            assert!(
                matches!(perfil_para(ruta), Err(Motivo::CaracterAmbiguo(_))),
                "se aceptó una ruta con comodín: {ruta}"
            );
        }
    }

    /// Una comilla o una barra invertida romperían el entrecomillado y podrían
    /// convertir el resto de la ruta en otra cosa.
    #[test]
    fn las_rutas_que_romperian_la_sintaxis_se_rechazan() {
        assert!(perfil_para("/home/x/co\"sa.AppImage").is_err());
        assert!(perfil_para("/home/x/co\\sa.AppImage").is_err());
        assert!(perfil_para("/home/x/dos\nlineas").is_err());
    }

    #[test]
    fn una_ruta_relativa_no_sirve_de_enganche() {
        assert_eq!(perfil_para("cosa.AppImage"), Err(Motivo::NoEsAbsoluta));
        assert_eq!(perfil_para(""), Err(Motivo::NoEsAbsoluta));
    }

    /// Dos rutas distintas no pueden compartir nombre de perfil: la segunda
    /// excepción pisaría a la primera y permitiría algo que nadie autorizó.
    #[test]
    fn rutas_distintas_dan_nombres_distintos() {
        let a = nombre_de("/a/b");
        let b = nombre_de("/a_b");
        assert_ne!(a, b, "dos rutas distintas colisionaron en el mismo nombre");

        let con_espacio = nombre_de("/x/App Monitor");
        let con_guion = nombre_de("/x/App-Monitor");
        assert_ne!(con_espacio, con_guion);
    }

    #[test]
    fn el_nombre_no_lleva_caracteres_raros() {
        let nombre = nombre_de("/home/pato/Apps/App Monitor_0.1.0.AppImage");
        assert!(
            nombre.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'),
            "el nombre del perfil quedó con caracteres que AppArmor no acepta: {nombre}"
        );
    }
}
