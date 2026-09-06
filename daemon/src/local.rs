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

/// Vuelve a compilar el perfil para que la excepción tenga efecto.
///
/// Hace falta porque el archivo de `local/` sólo se lee al compilar: escribirlo
/// no cambia nada hasta que el perfil se reemplaza. Sin esto la persona
/// apretaría «Permitir», no pasaría nada, y volvería a apretar.
///
/// El perfil se recompila desde donde vive, que **no** es `local/`: ahí está la
/// excepción, no el perfil. Se busca en los dos lugares posibles —los del
/// sistema en `/usr/share/apparmor.d` y los activados en `/etc/apparmor.d`—
/// porque un perfil puede estar en cualquiera de los dos según cómo se instaló.
pub fn recargar(perfil: &str) -> Result<(), String> {
    if !perfil_valido(perfil) {
        return Err(Motivo::PerfilInvalido.to_string());
    }
    let Some(archivo) = ubicar(perfil) else {
        return Err(format!("no encuentro el archivo del perfil '{perfil}'"));
    };

    let salida = std::process::Command::new("apparmor_parser")
        .arg("--replace")
        .arg(&archivo)
        .output()
        .map_err(|e| format!("no se pudo ejecutar apparmor_parser: {e}"))?;
    if salida.status.success() {
        return Ok(());
    }
    Err(format!(
        "apparmor_parser falló al recargar '{perfil}': {}",
        String::from_utf8_lossy(&salida.stderr).trim()
    ))
}

/// Dónde está el archivo de un perfil.
///
/// Los del paquete de perfiles viven en subdirectorios por letra
/// (`profiles-a-f/abook`), así que no alcanza con mirar en la raíz.
fn ubicar(perfil: &str) -> Option<PathBuf> {
    for raiz in ["/etc/apparmor.d", "/usr/share/apparmor.d"] {
        let directo = Path::new(raiz).join(perfil);
        if directo.is_file() {
            return Some(directo);
        }
        let Ok(entradas) = std::fs::read_dir(raiz) else {
            continue;
        };
        for e in entradas.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            let dentro = e.path().join(perfil);
            if dentro.is_file() {
                return Some(dentro);
            }
        }
    }
    None
}

// ── Lo que está bloqueado y todavía nadie decidió ────────────────────────────

use std::sync::{Arc, Mutex};

/// Un bloqueo que ocurrió y espera decisión.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Bloqueo {
    /// El perfil que lo produjo. Es también la identidad: se engancha al
    /// binario, así que es más estable que la ruta del proceso.
    pub perfil: String,
    pub ruta: String,
    pub mascara: String,
    /// De qué programa venía, si se pudo averiguar. Sólo para mostrar: el
    /// perfil es lo que manda.
    pub programa: String,
    /// Cuántas veces se repitió. Un programa que reintenta llena la lista de
    /// lo mismo, y lo que la persona necesita ver es una línea, no doscientas.
    pub veces: u32,
}

/// Techo de bloqueos recordados a la vez.
///
/// Un perfil recién puesto a hacer cumplir puede negar cientos de cosas en
/// segundos. Sin techo, la lista crece sin fin y la pantalla se vuelve
/// inservible justo cuando más se la necesita.
const MAXIMO: usize = 200;

pub type Pendientes = Arc<Mutex<Vec<Bloqueo>>>;

pub fn pendientes_nuevos() -> Pendientes {
    Arc::new(Mutex::new(Vec::new()))
}

/// Anota un bloqueo. Si ya estaba, sólo cuenta una repetición más.
///
/// Devuelve `true` si es la primera vez, que es cuando corresponde avisar: los
/// reintentos del mismo programa por lo mismo no son noticia nueva.
pub fn anotar(pendientes: &Pendientes, bloqueo: Bloqueo) -> bool {
    let Ok(mut lista) = pendientes.lock() else {
        return false;
    };
    if let Some(ya) = lista
        .iter_mut()
        .find(|b| b.perfil == bloqueo.perfil && b.ruta == bloqueo.ruta && b.mascara == bloqueo.mascara)
    {
        ya.veces = ya.veces.saturating_add(1);
        return false;
    }
    if lista.len() >= MAXIMO {
        return false;
    }
    lista.push(bloqueo);
    true
}

/// Lo que está esperando decisión.
pub fn listar(pendientes: &Pendientes) -> Vec<Bloqueo> {
    pendientes.lock().map(|l| l.clone()).unwrap_or_default()
}

/// Saca uno de la lista, ya decidido.
pub fn quitar(pendientes: &Pendientes, perfil: &str, ruta: &str) -> Option<Bloqueo> {
    let mut lista = pendientes.lock().ok()?;
    let i = lista.iter().position(|b| b.perfil == perfil && b.ruta == ruta)?;
    Some(lista.remove(i))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un directorio propio por prueba.
    ///
    /// El nombre lleva el de la prueba y no sólo el pid: las pruebas del mismo
    /// binario corren en hilos a la vez, así que con un directorio compartido
    /// una borraba lo que la otra acababa de escribir. Falló de verdad, y de
    /// forma intermitente, que es la peor manera de fallar.
    fn tmp(prueba: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("vasak-local-{}-{prueba}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }



    /// Que `ubicar` encuentre un perfil de verdad, no sólo uno inventado.
    ///
    /// Los del paquete viven en subdirectorios por letra —`profiles-a-f/abook`—
    /// y mirar sólo la raíz no los encuentra. Si esto se rompiera, «Permitir»
    /// escribiría la excepción y después fallaría al recargar, dejando el
    /// permiso concedido en el archivo y sin efecto en el kernel.
    #[test]
    fn se_encuentra_el_archivo_de_un_perfil_instalado() {
        // Sin el paquete de perfiles no hay nada que buscar, y eso no es una
        // falla de esta prueba.
        let Some(alguno) = std::fs::read_dir("/usr/share/apparmor.d")
            .ok()
            .and_then(|d| {
                d.flatten()
                    .filter(|e| e.path().is_dir())
                    .find_map(|e| {
                        std::fs::read_dir(e.path()).ok().and_then(|f| {
                            f.flatten()
                                .find(|x| x.path().is_file())
                                .map(|x| x.file_name().to_string_lossy().into_owned())
                        })
                    })
            })
        else {
            return;
        };

        assert!(
            ubicar(&alguno).is_some(),
            "no encontré el archivo de «{alguno}», que sí está instalado"
        );
        assert!(ubicar("no-existe-este-perfil-12345").is_none());
    }
    fn bloqueo(perfil: &str, ruta: &str) -> Bloqueo {
        Bloqueo {
            perfil: perfil.into(),
            ruta: ruta.into(),
            mascara: "r".into(),
            programa: "/usr/bin/x".into(),
            veces: 1,
        }
    }

    /// Un programa que reintenta no llena la lista: se cuenta y se avisa una
    /// vez. Doscientas líneas iguales harían la pantalla inservible justo
    /// cuando más se la necesita.
    #[test]
    fn lo_repetido_se_cuenta_y_avisa_una_sola_vez() {
        let p = pendientes_nuevos();
        assert!(anotar(&p, bloqueo("firefox", "/etc/x")));
        assert!(!anotar(&p, bloqueo("firefox", "/etc/x")));
        assert!(!anotar(&p, bloqueo("firefox", "/etc/x")));

        let lista = listar(&p);
        assert_eq!(lista.len(), 1);
        assert_eq!(lista[0].veces, 3);
    }

    #[test]
    fn bloqueos_distintos_son_entradas_distintas() {
        let p = pendientes_nuevos();
        anotar(&p, bloqueo("firefox", "/etc/uno"));
        anotar(&p, bloqueo("firefox", "/etc/dos"));
        anotar(&p, bloqueo("thunderbird", "/etc/uno"));
        assert_eq!(listar(&p).len(), 3);
    }

    /// El techo existe porque un perfil recién puesto a hacer cumplir puede
    /// negar cientos de cosas en segundos.
    #[test]
    fn la_lista_tiene_techo() {
        let p = pendientes_nuevos();
        for i in 0..(MAXIMO + 50) {
            anotar(&p, bloqueo("firefox", &format!("/etc/{i}")));
        }
        assert_eq!(listar(&p).len(), MAXIMO);
    }

    #[test]
    fn quitar_saca_el_que_se_decidio() {
        let p = pendientes_nuevos();
        anotar(&p, bloqueo("firefox", "/etc/uno"));
        anotar(&p, bloqueo("firefox", "/etc/dos"));

        assert!(quitar(&p, "firefox", "/etc/uno").is_some());
        assert_eq!(listar(&p).len(), 1);
        // Y no vuelve a salir el que ya no está.
        assert!(quitar(&p, "firefox", "/etc/uno").is_none());
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
        let raiz = tmp("conceder");
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
        let raiz = tmp("relectura");
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
        assert!(concedidas_en("nunca-tocado", &tmp("vacio")).is_empty());
    }
}
