//! Excepciones para cualquier perfil de AppArmor, no sólo los nuestros.
//!
//! # Por qué existe
//!
//! El sistema envía más de mil quinientos perfiles para los programas que trae
//! el escritorio. Cuando uno de ésos niega algo, hasta acá no pasaba nada: no
//! había aviso, no había entrada en ninguna lista, y no había forma de
//! permitirlo. La persona veía un programa que dejaba de andar sin explicación.
//!
//! Eso es lo que obliga a tenerlos en modo aviso en vez de haciéndolos cumplir.
//! La regla del escritorio es que **todo lo que se bloquea se pueda
//! desbloquear**, y sin este módulo esa regla no se cumplía para nada que no
//! fueran la cámara, el micrófono y las credenciales.
//!
//! # Cómo
//!
//! Los 1593 perfiles terminan con `include if exists <local/<nombre>>`, así que
//! alcanza con escribir ese archivo: no hay que tocar el perfil, que se
//! reemplaza en cada actualización del paquete.
//!
//! # Lo delicado
//!
//! Esto escribe reglas de política **como root**, a partir de rutas que eligió
//! el programa bloqueado: basta que intente abrir un archivo con el nombre que
//! quiera para que ese nombre llegue hasta acá por el registro del kernel. Una
//! ruta sin validar podría cerrar la regla y abrir otra —`x, /etc/shadow r, #`—
//! y concederse acceso a cualquier cosa mientras la persona cree que autorizó
//! un archivo suyo.
//!
//! Por eso la ruta va entre comillas **y** se rechaza todo lo que AppArmor
//! podría leer como algo que no es texto literal.
//!
//! Las comillas solas no alcanzan, y esto está medido contra
//! `apparmor_parser`, no supuesto:
//!
//! - `"/home/ana/x" rw, /etc/shadow r, "z" r,` —lo que saldría de una ruta que
//!   intenta cerrar la regla y abrir otra— **lo rechaza** el analizador. Ahí
//!   las comillas hacen su trabajo.
//! - `"/home/**" rw,` **lo acepta**. Entrecomillar no apaga los comodines de
//!   AppArmor. Un programa puede intentar abrir una ruta con `*`, y si se
//!   escribiera tal cual, la persona leería «quiere abrir /home/**», haría clic
//!   en Permitir creyendo que autoriza un archivo, y le estaría dando `/home`
//!   entero.
//!
//! El segundo caso es el que obliga a rechazar caracteres y no confiar en la
//! sintaxis. Y rechazar en vez de escapar, porque ninguno de esos caracteres
//! aparece en el nombre de un archivo que a alguien le interese permitir.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Dónde viven los archivos de excepción. Es la ruta que resuelve el
/// `include if exists <local/…>` de cada perfil.
const LOCAL: &str = "/etc/apparmor.d/local";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Motivo {
    NoEsAbsoluta,
    /// Un carácter que AppArmor leería como comodín o que rompería el archivo.
    CaracterAmbiguo(char),
    /// El nombre del perfil no sirve como nombre de archivo.
    PerfilInvalido,
    /// Permisos que no son un conjunto conocido.
    MascaraInvalida,
}

impl std::fmt::Display for Motivo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Motivo::NoEsAbsoluta => write!(f, "la ruta no es absoluta"),
            Motivo::CaracterAmbiguo(c) => {
                write!(f, "la ruta lleva «{c}», que AppArmor no leería como texto")
            }
            Motivo::PerfilInvalido => write!(f, "el nombre del perfil no es utilizable"),
            Motivo::MascaraInvalida => write!(f, "los permisos no son un conjunto conocido"),
        }
    }
}

/// Lo que no puede aparecer en una ruta que vamos a escribir en una regla.
///
/// Los comodines de AppArmor (`* ? [ ] { }`), lo que rompe la cadena entre
/// comillas (`"` y `\`), lo que corta la línea (`\n`, `\r`) y lo que separa o
/// termina una regla (`,` y `#`). Ninguno aparece en el nombre real de un
/// archivo que a alguien le interese permitir, así que rechazar es mejor que
/// escapar: escapar dejaría pasar una ruta absurda y la escribiría igual.
const AMBIGUOS: &[char] = &[
    '*', '?', '[', ']', '{', '}', '"', '\\', '\n', '\r', ',', '#', '\0',
];

/// Los permisos que AppArmor entiende para un archivo.
///
/// `x` queda afuera a propósito: no es un permiso más. Conceder ejecución
/// necesita además decir bajo qué perfil se ejecuta —`ix`, `Px`, `Ux`— y cada
/// una de esas letras cambia si el programa nuevo queda confinado o no. Un
/// «permitir» de un clic no puede decidir eso.
const PERMISOS: &[char] = &['r', 'w', 'a', 'l', 'k', 'm'];

/// Si el nombre del perfil sirve como nombre de archivo dentro de `local/`.
///
/// El nombre viene del registro del kernel, así que se comprueba en vez de
/// confiarse: un `../../etc/passwd` escribiría fuera del directorio.
pub fn perfil_valido(perfil: &str) -> bool {
    !perfil.is_empty()
        && perfil.len() <= 200
        && perfil != "."
        && perfil != ".."
        && perfil
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Los permisos, normalizados y ordenados, o un error.
pub fn mascara_valida(mascara: &str) -> Result<String, Motivo> {
    if mascara.is_empty() || mascara.len() > PERMISOS.len() {
        return Err(Motivo::MascaraInvalida);
    }
    let mut letras: BTreeSet<char> = BTreeSet::new();
    for c in mascara.chars() {
        if !PERMISOS.contains(&c) {
            return Err(Motivo::MascaraInvalida);
        }
        letras.insert(c);
    }
    Ok(letras.into_iter().collect())
}

/// La línea de regla para permitir esa ruta con esos permisos.
///
/// La ruta va entre comillas porque los nombres de archivo llevan espacios, y
/// una regla sin comillas terminaría en el primer espacio dejando el resto como
/// basura sintáctica. Pero las comillas **no** son la defensa: la defensa es
/// haber rechazado antes todo lo que AppArmor no leería literal.
pub fn regla_para(ruta: &str, mascara: &str) -> Result<String, Motivo> {
    if !ruta.starts_with('/') {
        return Err(Motivo::NoEsAbsoluta);
    }
    if let Some(c) = ruta.chars().find(|c| AMBIGUOS.contains(c)) {
        return Err(Motivo::CaracterAmbiguo(c));
    }
    let permisos = mascara_valida(mascara)?;
    Ok(format!("\"{ruta}\" {permisos},"))
}

/// El archivo de excepciones de un perfil.
fn archivo_de(perfil: &str, raiz: &Path) -> PathBuf {
    raiz.join(perfil)
}

const CABECERA: &str = "\
# ARCHIVO GENERADO — no editar a mano.
#
# Lo que se le permitió a este perfil desde Configuración, además de lo que su
# perfil trae. El perfil lo carga con `include if exists <local/…>`, así que
# esto sobrevive a que el paquete de perfiles se actualice.
#
# Borrar una línea vuelve a bloquear eso.
";

/// Las reglas ya concedidas a un perfil.
pub fn concedidas_en(perfil: &str, raiz: &Path) -> Vec<String> {
    let Ok(texto) = std::fs::read_to_string(archivo_de(perfil, raiz)) else {
        return Vec::new();
    };
    texto
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Agrega una regla, sin repetirla.
///
/// Devuelve si el archivo cambió: si la regla ya estaba, no hay nada que
/// recargar y decirlo evita un `apparmor_parser` por cada clic repetido.
pub fn conceder_en(perfil: &str, regla: &str, raiz: &Path) -> Result<bool, String> {
    if !perfil_valido(perfil) {
        return Err(Motivo::PerfilInvalido.to_string());
    }

    let mut reglas = concedidas_en(perfil, raiz);
    if reglas.iter().any(|r| r == regla) {
        return Ok(false);
    }
    reglas.push(regla.to_string());
    escribir(perfil, &reglas, raiz)?;
    Ok(true)
}

/// Quita una regla. Si no queda ninguna, borra el archivo en vez de dejarlo
/// vacío: un archivo con sólo la cabecera confunde a quien lo lea.
pub fn revocar_en(perfil: &str, regla: &str, raiz: &Path) -> Result<bool, String> {
    if !perfil_valido(perfil) {
        return Err(Motivo::PerfilInvalido.to_string());
    }
    let antes = concedidas_en(perfil, raiz);
    let despues: Vec<String> = antes.iter().filter(|r| *r != regla).cloned().collect();
    if despues.len() == antes.len() {
        return Ok(false);
    }
    if despues.is_empty() {
        let _ = std::fs::remove_file(archivo_de(perfil, raiz));
    } else {
        escribir(perfil, &despues, raiz)?;
    }
    Ok(true)
}

fn escribir(perfil: &str, reglas: &[String], raiz: &Path) -> Result<(), String> {
    std::fs::create_dir_all(raiz).map_err(|e| format!("no se pudo crear {}: {e}", raiz.display()))?;
    let mut texto = String::from(CABECERA);
    for r in reglas {
        texto.push_str("  ");
        texto.push_str(r);
        texto.push('\n');
    }
    let destino = archivo_de(perfil, raiz);
    std::fs::write(&destino, texto).map_err(|e| format!("no se pudo escribir {}: {e}", destino.display()))
}

/// Dónde escribir de verdad. Se puede desviar para las pruebas.
pub fn raiz() -> PathBuf {
    std::env::var_os("VASAK_PERMISSIONS_LOCAL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(LOCAL))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("vasak-local-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// El caso que justifica toda la validación: la ruta la elige el programa
    /// bloqueado, y una regla mal formada le daría acceso a lo que quiera
    /// mientras la persona cree que autorizó un archivo suyo.
    #[test]
    fn una_ruta_que_intenta_abrir_otra_regla_se_rechaza() {
        for ruta in [
            "/home/ana/x, /etc/shadow r, #",
            "/home/ana/x\" rw, /** rw, \"",
            "/home/ana/x\n  /etc/shadow r,",
            "/home/ana/x#comentario",
        ] {
            assert!(regla_para(ruta, "r").is_err(), "pasó: {ruta}");
        }
    }

    /// Los comodines también, aunque vayan entre comillas: en AppArmor
    /// entrecomillar no apaga el globbing.
    #[test]
    fn los_comodines_se_rechazan() {
        for ruta in ["/home/ana/*", "/home/**", "/home/ana/x?", "/home/{ana,juan}/x"] {
            assert!(regla_para(ruta, "r").is_err(), "pasó: {ruta}");
        }
    }

    #[test]
    fn una_ruta_normal_da_una_regla_entrecomillada() {
        assert_eq!(
            regla_para("/home/ana/Documentos/mi archivo.txt", "rw"),
            Ok("\"/home/ana/Documentos/mi archivo.txt\" rw,".to_string())
        );
    }

    #[test]
    fn la_ruta_tiene_que_ser_absoluta() {
        assert_eq!(regla_para("documentos/x", "r"), Err(Motivo::NoEsAbsoluta));
        assert_eq!(regla_para("", "r"), Err(Motivo::NoEsAbsoluta));
    }

    /// La ejecución no se concede con un clic: `x` a secas no dice bajo qué
    /// perfil corre lo que se ejecuta, y esa elección decide si el programa
    /// nuevo queda confinado o suelto.
    #[test]
    fn la_ejecucion_no_es_un_permiso_que_se_conceda_asi() {
        assert_eq!(regla_para("/home/ana/x", "rx"), Err(Motivo::MascaraInvalida));
        assert_eq!(regla_para("/home/ana/x", "ix"), Err(Motivo::MascaraInvalida));
        assert_eq!(regla_para("/home/ana/x", "Px"), Err(Motivo::MascaraInvalida));
    }

    #[test]
    fn la_mascara_se_normaliza_y_se_valida() {
        assert_eq!(mascara_valida("wr"), Ok("rw".to_string()));
        assert_eq!(mascara_valida("rrr"), Ok("r".to_string()));
        assert_eq!(mascara_valida(""), Err(Motivo::MascaraInvalida));
        assert_eq!(mascara_valida("z"), Err(Motivo::MascaraInvalida));
    }

    /// El nombre del perfil también viene del registro del kernel y termina
    /// siendo un nombre de archivo.
    #[test]
    fn un_perfil_que_se_escapa_del_directorio_se_rechaza() {
        for p in ["../../etc/passwd", "a/b", "..", ".", "", "con espacio", "x\0y"] {
            assert!(!perfil_valido(p), "pasó: {p}");
        }
        for p in ["firefox", "thunderbird", "usr.bin.foo", "vasak-appimage"] {
            assert!(perfil_valido(p), "no pasó: {p}");
        }
    }

    #[test]
    fn conceder_escribe_revocar_borra_y_no_se_repite() {
        let raiz = tmp();
        let regla = regla_para("/home/ana/x.txt", "rw").unwrap();

        assert_eq!(conceder_en("firefox", &regla, &raiz), Ok(true));
        assert_eq!(concedidas_en("firefox", &raiz), vec![regla.clone()]);
        // Segunda vez: no cambia nada, así que no hace falta recargar.
        assert_eq!(conceder_en("firefox", &regla, &raiz), Ok(false));

        assert_eq!(revocar_en("firefox", &regla, &raiz), Ok(true));
        assert!(concedidas_en("firefox", &raiz).is_empty());
        // Sin reglas, el archivo no queda vacío: no queda.
        assert!(!archivo_de("firefox", &raiz).exists());

        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Lo escrito tiene que volver a leerse igual, o revocar no encontraría
    /// nunca la regla que quiere sacar.
    #[test]
    fn lo_escrito_se_relee_identico() {
        let raiz = tmp();
        let reglas: Vec<String> = ["/home/ana/uno", "/home/ana/dos con espacio", "/etc/hosts"]
            .iter()
            .map(|r| regla_para(r, "r").unwrap())
            .collect();
        for r in &reglas {
            conceder_en("prueba", r, &raiz).unwrap();
        }
        assert_eq!(concedidas_en("prueba", &raiz), reglas);
        let _ = std::fs::remove_dir_all(&raiz);
    }

    #[test]
    fn un_perfil_sin_excepciones_no_tiene_reglas() {
        assert!(concedidas_en("nunca-tocado", &tmp()).is_empty());
    }
}
