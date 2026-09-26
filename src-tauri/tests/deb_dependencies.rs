//! Las dependencias del `.deb`, contra lo que el agente enlaza.
//!
//! La lista venía copiada de la plantilla `vapp` y no tenía relación con el
//! binario: declaraba `libsoup2.4-1` **y** `libsoup-3.0-0` a la vez, más dos
//! paquetes que no son bibliotecas. Se corrigió contra `readelf -d … | grep
//! NEEDED` del binario de release; esto cuida que no vuelva a derivar hacia
//! lo mismo.

const CONFIG: &str = include_str!("../tauri.conf.json");

fn deb_depends() -> Vec<String> {
    let config: serde_json::Value = serde_json::from_str(CONFIG).expect("tauri.conf.json válido");
    config["bundle"]["linux"]["deb"]["depends"]
        .as_array()
        .expect("bundle.linux.deb.depends es una lista")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("cada dependencia es texto")
                .to_string()
        })
        .collect()
}

/// WebKitGTK 4.1 es la generación que enlaza libsoup 3, y las dos
/// generaciones de libsoup no pueden convivir en un proceso. Declarar la 2.4
/// ata el paquete a una biblioteca que el agente no puede cargar.
#[test]
fn declara_una_sola_generacion_de_libsoup() {
    let depends = deb_depends();
    assert!(depends.iter().any(|d| d == "libsoup-3.0-0"));
    assert!(
        !depends.iter().any(|d| d.starts_with("libsoup2.4")),
        "libsoup 2.4 no la enlaza nadie: {depends:?}"
    );
}

/// Lo que el binario enlaza y viene de la pila gráfica tiene que estar. Son
/// los `NEEDED` de `readelf` traducidos a nombres de Debian.
#[test]
fn declara_lo_que_el_agente_enlaza() {
    let depends = deb_depends();
    for needed in [
        "libwebkit2gtk-4.1-0",
        "libjavascriptcoregtk-4.1-0",
        "libgtk-3-0t64",
        "libgdk-pixbuf-2.0-0",
        "libcairo2",
        "libglib2.0-0t64",
        "libdbus-1-3",
        "libsoup-3.0-0",
    ] {
        assert!(
            depends.iter().any(|d| d == needed),
            "falta {needed}: {depends:?}"
        );
    }
}

/// Y nada que no sea una biblioteca enlazada: declarar de más ata el paquete
/// a cosas que no usa, igual de mal que declarar de menos.
#[test]
fn no_declara_lo_que_el_agente_no_enlaza() {
    let depends = deb_depends();
    for unused in ["desktop-file-utils", "hicolor-icon-theme", "libpango-1.0-0"] {
        assert!(
            !depends.iter().any(|d| d == unused),
            "{unused} no aparece en los NEEDED del agente: {depends:?}"
        );
    }
    let mut unique = depends.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), depends.len(), "hay repetidas: {depends:?}");
}
