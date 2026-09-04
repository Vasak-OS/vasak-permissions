//! El perfil generado tiene que compilar con el AppArmor de verdad.
//!
//! Las pruebas unitarias del módulo comprueban el texto contra sí mismo, que no
//! alcanza: un perfil puede leerse bien y no compilar. Y un perfil que no
//! compila significa que «permitir» no permite, en silencio, en la máquina de
//! alguien.
//!
//! Se salta cuando `apparmor_parser` no está instalado —no todas las máquinas
//! donde se compila esto lo tienen— en vez de fallar, que sería confundir «no
//! se pudo comprobar» con «está mal».

use std::process::Command;

/// Copiado del módulo: el crate es un binario, así que las pruebas de
/// integración no pueden importarlo. Si el formato cambia allá y no acá, esta
/// prueba deja de valer, así que compara contra un perfil generado a mano con
/// la misma forma.
fn perfil_con(nombre: &str, ruta: &str, negaciones: &str) -> String {
    format!(
        "abi <abi/4.0>,\ninclude <tunables/global>\nprofile {nombre} \"{ruta}\" {{\n  \
         file,\n  network,\n  unix,\n  signal,\n  ptrace,\n  dbus,\n  capability,\n  \
         mount,\n  umount,\n  pivot_root,\n  change_profile,\n  io_uring,\n  mqueue,\n  \
         userns,\n{negaciones}\n}}\n"
    )
}

fn perfil(nombre: &str, ruta: &str) -> String {
    perfil_con(nombre, ruta, "")
}

fn hay_parser() -> bool {
    Command::new("apparmor_parser")
        .arg("--version")
        .output()
        .is_ok_and(|salida| salida.status.success())
}

fn compila(texto: &str) -> Result<(), String> {
    let archivo = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    std::fs::write(archivo.path(), texto).map_err(|e| e.to_string())?;
    let salida = Command::new("apparmor_parser")
        .arg("-Q")
        .arg(archivo.path())
        .output()
        .map_err(|e| e.to_string())?;
    if salida.status.success() {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&salida.stderr).into_owned())
}

#[test]
fn el_perfil_generado_lo_acepta_apparmor() {
    if !hay_parser() {
        eprintln!("apparmor_parser no está instalado; se salta la comprobación");
        return;
    }
    let texto = perfil("vasak-permitida-prueba", "/home/alguien/Apps/cosa.AppImage");
    if let Err(error) = compila(&texto) {
        panic!("el perfil generado no compila:\n{error}\n\nperfil:\n{texto}");
    }
}

/// El caso que motivó el entrecomillado: el AppImage del equipo de pruebas
/// tiene espacios en el nombre, y sin comillas AppArmor leería la ruta hasta el
/// primer espacio.
#[test]
fn una_ruta_con_espacios_tambien_compila() {
    if !hay_parser() {
        eprintln!("apparmor_parser no está instalado; se salta la comprobación");
        return;
    }
    let texto = perfil(
        "vasak-permitida-con-espacios",
        "/home/alguien/Apps/App Monitor_0.1.0_amd64.AppImage",
    );
    if let Err(error) = compila(&texto) {
        panic!("una ruta con espacios no compila:\n{error}");
    }
}

/// El caso parcial: se permitió la cámara y el micrófono sigue negado.
///
/// Importa aparte porque mezcla reglas amplias con una negación, y una negación
/// mal escrita no siempre falla al compilar: puede compilar y no negar.
#[test]
fn un_perfil_con_una_negacion_tambien_compila() {
    if !hay_parser() {
        eprintln!("apparmor_parser no está instalado; se salta la comprobación");
        return;
    }
    let texto = perfil_con(
        "vasak-permitida-parcial",
        "/home/alguien/Apps/cosa.AppImage",
        "  audit deny /dev/snd/pcmC*D*c rwk,",
    );
    if let Err(error) = compila(&texto) {
        panic!("el perfil parcial no compila:\n{error}\n\nperfil:\n{texto}");
    }
}
