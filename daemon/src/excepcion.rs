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

use vasak_permissions_protocol::Resource;

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
/// Con qué empieza el nombre de todo perfil de excepción.
///
/// Es también lo que el vigilante del registro usa para reconocerlos, así que
/// vive acá y no escrito dos veces: separarlos dejaría los bloqueos de una
/// aplicación con excepción sin aviso ninguno.
pub const PREFIJO: &str = "vasak-permitida";

pub fn nombre_de(ruta: &str) -> String {
    let mut nombre = String::from(PREFIJO);
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

/// Lo que el perfil general niega, y cómo se escribe cada negación.
///
/// Tiene que ser lo mismo que hay en `/etc/apparmor.d/vasak-appimage`: si allá
/// se agrega una negación y acá no, una excepción parcial la levantaría sin
/// querer.
pub(crate) const NEGACIONES: &[(Resource, &[&str])] = &[
    (Resource::Camera, &["audit deny /dev/video* rwk,"]),
    (Resource::Microphone, &["audit deny /dev/snd/pcmC*D*c rwk,"]),
    // Las credenciales son varias reglas y una sola decisión. Están juntas
    // porque preguntarlas por separado sería pedirle a la persona que
    // distinga entre confiarle a un programa su clave de SSH y confiarle la
    // de GPG, que es una distinción que nadie hace.
    //
    // `rwkl` y no `rwk`: sin la `l` se puede crear un enlace duro al archivo
    // desde fuera del directorio negado y leerlo por ahí, que deja la valla
    // en decorado.
    (
        Resource::Credentials,
        &[
            "audit deny @{HOME}/.ssh/** rwkl,",
            "audit deny @{HOME}/.gnupg/** rwkl,",
            // El llavero del escritorio: su base guarda todas las contraseñas
            // de la sesión.
            "audit deny @{HOME}/.local/share/vasak-keyring/** rwkl,",
            // El agente de SSH es peor que la clave: con el socket no hace
            // falta leer ningún archivo para firmar con ella.
            "audit deny /run/user/*/ssh-agent.socket rw,",
            "audit deny /run/user/*/gnupg/** rw,",
            // Los que valen una sesión entera sin ser una clave.
            "audit deny @{HOME}/.netrc rwkl,",
            "audit deny @{HOME}/.git-credentials rwkl,",
            "audit deny @{HOME}/.npmrc rwkl,",
            "audit deny @{HOME}/.aws/** rwkl,",
            "audit deny @{HOME}/.kube/** rwkl,",
            "audit deny @{HOME}/.config/gh/** rwkl,",
            "audit deny @{HOME}/.docker/config.json rwkl,",
        ],
    ),
];

/// El texto del perfil de excepción para esa ruta.
///
/// `permitidos` son los recursos que esta aplicación **sí** puede usar. Los que
/// no estén en esa lista se siguen negando acá.
///
/// Esa distinción es el punto: una excepción sin negaciones devolvería de una
/// vez todo lo que el perfil general quita, así que permitir la cámara
/// permitiría también el micrófono. Un permiso que concede de más es peor que
/// no tenerlo, porque quien lo dio cree que dio otra cosa.
pub fn perfil_para(ruta: &str, permitidos: &[Resource]) -> Result<String, Motivo> {
    if !ruta.starts_with('/') {
        return Err(Motivo::NoEsAbsoluta);
    }
    if let Some(c) = ruta.chars().find(|c| AMBIGUOS.contains(c)) {
        return Err(Motivo::CaracterAmbiguo(c));
    }

    let negaciones: String = NEGACIONES
        .iter()
        .filter(|(recurso, _)| !permitidos.contains(recurso))
        .flat_map(|(_, reglas)| reglas.iter())
        .map(|regla| format!("\n  {regla}\n"))
        .collect();

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
  # Todo permitido, y después se vuelve a negar lo que esta aplicación no tiene
  # concedido. Sin las negaciones de abajo, la excepción devolvería de una vez
  # todo lo que el perfil general quita.
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
{negaciones}
  include if exists <local/{nombre}>
}}
"#,
        nombre = nombre_de(ruta),
        ruta = ruta,
        negaciones = negaciones,
    ))
}

// ── Ponerlas y sacarlas ─────────────────────────────────────────────────────

/// Dónde viven los perfiles de excepción.
///
/// El mismo directorio que los demás, y con el prefijo `vasak-`, para que el
/// cargador del sistema —que toma `/etc/apparmor.d/vasak-*`— los cargue solos
/// en cada arranque. Una excepción tiene que sobrevivir al reinicio: es una
/// decisión que la persona tomó, no un estado de la sesión.
const DIRECTORIO: &str = "/etc/apparmor.d";

/// Aplica lo decidido para una aplicación.
///
/// `permitidos` es la lista completa de lo que esa aplicación tiene concedido,
/// no un agregado: se pasa entera cada vez y el perfil se reescribe. Así el
/// archivo en disco siempre refleja la decisión guardada, en lugar de ser el
/// resultado de una sucesión de cambios que puede haberse desincronizado.
///
/// Sin nada permitido no queda un perfil que no permite nada: se **borra**. El
/// perfil general vuelve a ser el que engancha, que es exactamente el estado
/// original.
pub fn aplicar(binary_path: &str, permitidos: &[Resource]) -> Result<(), String> {
    let archivo = std::path::Path::new(DIRECTORIO).join(nombre_de(binary_path));

    if permitidos.is_empty() {
        if !archivo.exists() {
            return Ok(());
        }
        // Se descarga antes de borrar: al revés, el perfil quedaría cargado en
        // el kernel sin archivo que lo respalde, y seguiría permitiendo hasta
        // el próximo reinicio sin que nada lo delate.
        descargar(&archivo)?;
        return std::fs::remove_file(&archivo)
            .map_err(|e| format!("no se pudo borrar {}: {e}", archivo.display()));
    }

    let contenido = perfil_para(binary_path, permitidos).map_err(|motivo| motivo.to_string())?;
    std::fs::write(&archivo, contenido)
        .map_err(|e| format!("no se pudo escribir {}: {e}", archivo.display()))?;
    cargar(&archivo)
}

fn cargar(archivo: &std::path::Path) -> Result<(), String> {
    correr_parser(&["--replace"], archivo)
}

fn descargar(archivo: &std::path::Path) -> Result<(), String> {
    correr_parser(&["--remove"], archivo)
}

fn correr_parser(argumentos: &[&str], archivo: &std::path::Path) -> Result<(), String> {
    let salida = std::process::Command::new("apparmor_parser")
        .args(argumentos)
        .arg(archivo)
        .output()
        .map_err(|e| format!("no se pudo ejecutar apparmor_parser: {e}"))?;
    if salida.status.success() {
        return Ok(());
    }
    Err(format!(
        "apparmor_parser falló: {}",
        String::from_utf8_lossy(&salida.stderr).trim()
    ))
}

/// Los recursos de hardware que una aplicación tiene concedidos.
///
/// Sólo los que el perfil general niega: el resto no se representa en AppArmor,
/// así que ponerlo en la excepción no cambiaría nada y confundiría a quien lea
/// el archivo.
pub fn permitidos_de(
    policy: &crate::policy::UserPolicy,
    binary_path: &str,
) -> Vec<Resource> {
    NEGACIONES
        .iter()
        .map(|(recurso, _)| recurso)
        .filter(|recurso| policy.decision(binary_path, &recurso.as_id()).is_allowed())
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use vasak_permissions_protocol::{Application, Decision, Provenance};

    fn una_app(ruta: &str) -> Application {
        Application {
            binary_path: ruta.to_string(),
            display_name: "prueba".into(),
            provenance: Provenance::Unverified,
        }
    }

    /// Lo concedido sale de la política guardada, no de lo que se acaba de
    /// tocar: si no, cambiar el micrófono reescribiría el perfil olvidando que
    /// la cámara ya estaba permitida.
    /// Permitir las credenciales las levanta **todas**: es una sola decisión.
    #[test]
    fn permitir_credenciales_levanta_todas_sus_negaciones() {
        let con = perfil_para("/home/x/a.AppImage", &[Resource::Credentials]).unwrap();
        assert!(!con.contains(".ssh"), "quedó negado ~/.ssh");
        assert!(!con.contains(".gnupg"));
        assert!(!con.contains("ssh-agent"));
        assert!(!con.contains("vasak-keyring"));
        // Y no toca lo otro: quien permitió las claves no permitió la cámara.
        assert!(con.contains("deny /dev/video*"));
    }

    /// Y no permitirlas las mantiene todas, sin que se escape ninguna.
    #[test]
    fn sin_permiso_se_niegan_todas_las_credenciales() {
        let sin = perfil_para("/home/x/a.AppImage", &[Resource::Camera]).unwrap();
        let reglas = NEGACIONES
            .iter()
            .find(|(r, _)| *r == Resource::Credentials)
            .unwrap()
            .1;
        for regla in reglas {
            assert!(sin.contains(regla), "falta en el perfil: {regla}");
        }
    }

    /// El agente de SSH se niega junto con la clave.
    ///
    /// Negar `~/.ssh` y dejar el socket del agente sería seguridad de mentira:
    /// con el socket no hace falta leer ningún archivo para firmar con la
    /// clave. Van juntos o no sirve ninguno.
    #[test]
    fn el_agente_va_con_la_clave() {
        let reglas = NEGACIONES
            .iter()
            .find(|(r, _)| *r == Resource::Credentials)
            .unwrap()
            .1;
        assert!(reglas.iter().any(|r| r.contains(".ssh/")));
        assert!(reglas.iter().any(|r| r.contains("ssh-agent.socket")));
    }

    /// Los enlaces duros cuentan.
    ///
    /// Sin la `l`, se puede crear un enlace al archivo desde afuera del
    /// directorio negado y leerlo por ahí — la valla queda de decorado. Los
    /// sockets van sin `l` porque no se enlazan.
    #[test]
    fn las_negaciones_de_archivo_cubren_el_enlace_duro() {
        let reglas = NEGACIONES
            .iter()
            .find(|(r, _)| *r == Resource::Credentials)
            .unwrap()
            .1;
        for regla in reglas.iter().filter(|r| r.contains("@{HOME}")) {
            assert!(regla.contains("rwkl,"), "sin enlace duro: {regla}");
        }
    }

    #[test]
    fn lo_permitido_se_lee_de_la_politica_entera() {
        let mut politica = crate::policy::UserPolicy::default();
        let app = una_app("/home/x/a.AppImage");
        politica.record(&app, "camera", Decision::Allowed);
        politica.record(&app, "microphone", Decision::Denied);

        let permitidos = permitidos_de(&politica, "/home/x/a.AppImage");
        assert_eq!(permitidos, vec![Resource::Camera]);
    }

    #[test]
    fn una_aplicacion_sin_nada_decidido_no_tiene_permitido_nada() {
        let politica = crate::policy::UserPolicy::default();
        assert!(permitidos_de(&politica, "/home/x/a.AppImage").is_empty());
    }

    /// Los recursos que AppArmor no representa no entran en la excepción, aunque
    /// estén concedidos: ponerlos ahí no cambiaría nada y confundiría a quien
    /// lea el archivo.
    #[test]
    fn los_recursos_que_apparmor_no_niega_no_entran() {
        let mut politica = crate::policy::UserPolicy::default();
        let app = una_app("/home/x/a.AppImage");
        politica.record(&app, "screen-capture", Decision::Allowed);
        politica.record(&app, "account.email", Decision::Allowed);

        assert!(permitidos_de(&politica, "/home/x/a.AppImage").is_empty());
    }

    #[test]
    fn el_perfil_engancha_la_ruta_exacta_y_no_niega_nada() {
        let perfil = perfil_para("/home/alguien/Apps/cosa.AppImage", &[Resource::Camera, Resource::Microphone]).unwrap();
        assert!(perfil.contains(r#""/home/alguien/Apps/cosa.AppImage""#));
        assert!(perfil.contains("file,"));
    }

    /// El caso real: el AppImage del equipo de pruebas tiene espacios.
    #[test]
    fn una_ruta_con_espacios_se_acepta_y_queda_entre_comillas() {
        let perfil = perfil_para("/home/pato/Apps/App Monitor_0.1.0.AppImage", &[Resource::Camera, Resource::Microphone]).unwrap();
        assert!(perfil.contains(r#""/home/pato/Apps/App Monitor_0.1.0.AppImage""#));
    }

    /// Lo importante de todo el módulo. Una ruta con comodines produciría una
    /// excepción que cubre aplicaciones que nadie autorizó.
    /// El motivo de todo este cambio: permitir la cámara no puede regalar el
    /// micrófono de yapa.
    #[test]
    fn permitir_uno_no_permite_el_otro() {
        let solo_camara = perfil_para("/home/x/a.AppImage", &[Resource::Camera]).unwrap();
        assert!(
            !solo_camara.contains("/dev/video"),
            "sigue negando la cámara, que es lo que se permitió"
        );
        assert!(
            solo_camara.contains("deny /dev/snd/pcmC*D*c"),
            "dejó de negar el micrófono, que nadie permitió"
        );
    }

    #[test]
    fn permitir_el_microfono_es_simetrico() {
        let solo_micro = perfil_para("/home/x/a.AppImage", &[Resource::Microphone]).unwrap();
        assert!(solo_micro.contains("deny /dev/video*"));
        assert!(!solo_micro.contains("/dev/snd"));
    }

    /// Una excepción sin nada permitido no tiene sentido, pero si llegara no
    /// puede terminar concediendo: tiene que negar todo lo que el general niega.
    #[test]
    fn una_excepcion_vacia_no_concede_nada() {
        let ninguno = perfil_para("/home/x/a.AppImage", &[]).unwrap();
        assert!(ninguno.contains("deny /dev/video*"));
        assert!(ninguno.contains("deny /dev/snd/pcmC*D*c"));
    }

    /// Y el caso completo sí devuelve todo.
    ///
    /// «Completo» se recorre desde la tabla y no se escribe a mano: con la
    /// lista fija, agregar una negación nueva dejaba esta prueba pasando por
    /// la razón equivocada —seguiría permitiendo sólo dos cosas y afirmando
    /// que no queda ninguna negación—. Pasó al sumar las credenciales.
    #[test]
    fn permitirlo_todo_no_deja_ninguna_negacion() {
        let todos: Vec<Resource> = NEGACIONES.iter().map(|(r, _)| r.clone()).collect();
        let completo = perfil_para("/home/x/a.AppImage", &todos).unwrap();
        assert!(
            !completo.contains("deny"),
            "quedó una negación con todo permitido:\n{completo}"
        );
    }

    /// Una excepción vacía tiene que negar **todo** lo de la tabla, no sólo lo
    /// que alguien se acordó de listar acá.
    #[test]
    fn una_excepcion_vacia_niega_todo_lo_de_la_tabla() {
        let ninguno = perfil_para("/home/x/a.AppImage", &[]).unwrap();
        for (_, reglas) in NEGACIONES {
            for regla in *reglas {
                assert!(ninguno.contains(regla), "falta en el perfil: {regla}");
            }
        }
    }

    #[test]
    fn las_rutas_con_comodines_se_rechazan() {
        for ruta in [
            "/home/x/todo*.AppImage",
            "/home/x/cosa?.AppImage",
            "/home/x/[ab].AppImage",
            "/home/x/{a,b}.AppImage",
        ] {
            assert!(
                matches!(perfil_para(ruta, &[]), Err(Motivo::CaracterAmbiguo(_))),
                "se aceptó una ruta con comodín: {ruta}"
            );
        }
    }

    /// Una comilla o una barra invertida romperían el entrecomillado y podrían
    /// convertir el resto de la ruta en otra cosa.
    #[test]
    fn las_rutas_que_romperian_la_sintaxis_se_rechazan() {
        assert!(perfil_para("/home/x/co\"sa.AppImage", &[]).is_err());
        assert!(perfil_para("/home/x/co\\sa.AppImage", &[Resource::Camera, Resource::Microphone]).is_err());
        assert!(perfil_para("/home/x/dos\nlineas", &[Resource::Camera, Resource::Microphone]).is_err());
    }

    #[test]
    fn una_ruta_relativa_no_sirve_de_enganche() {
        assert_eq!(perfil_para("cosa.AppImage", &[Resource::Camera, Resource::Microphone]), Err(Motivo::NoEsAbsoluta));
        assert_eq!(perfil_para("", &[Resource::Camera, Resource::Microphone]), Err(Motivo::NoEsAbsoluta));
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
