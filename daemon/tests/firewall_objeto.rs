//! El objeto BPF commiteado tiene que corresponder a su fuente.
//!
//! El daemon no compila el programa BPF: lo embebe ya compilado
//! (`src/firewall/vasak-firewall.bpf.o`), para que su build siga siendo estable
//! y sin `bpf-linker` ni nightly. El riesgo de eso es que alguien edite
//! `firewall-ebpf/src/main.rs` y se olvide de regenerar el objeto —y entonces el
//! daemon haría cumplir una versión vieja del programa sin que nada avise—.
//!
//! Esta prueba recompila el crate `firewall-ebpf` y compara byte a byte con el
//! objeto commiteado. La compilación es determinista (verificado: `clang`/LLVM
//! con `debug = false` y un programa diminuto da siempre el mismo ELF), así que
//! la comparación exacta es válida.
//!
//! Se **salta** —no falla— cuando falta el toolchain BPF (nightly con `rust-src`
//! o `bpf-linker`), que es el caso del CI del taller, que corre estable. El
//! salteo es determinista y marcado, como la nota `test-con-unshare-hunde-...`:
//! una prueba que no puede correr sin el toolchain no debe hundir la cobertura.

use std::path::{Path, PathBuf};
use std::process::Command;

/// La raíz del crate del daemon (`daemon/`), de donde cuelgan las dos rutas.
fn daemon_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn crate_ebpf() -> PathBuf {
    daemon_dir().join("../firewall-ebpf")
}

fn objeto_commiteado() -> PathBuf {
    daemon_dir().join("src/firewall/vasak-firewall.bpf.o")
}

fn objeto_recompilado() -> PathBuf {
    crate_ebpf().join("target/bpfel-unknown-none/release/vasak-firewall")
}

/// El canal fijado en el `rust-toolchain.toml` del crate BPF (p. ej.
/// `nightly-2026-11-04`). La correspondencia es byte a byte y el codegen de LLVM
/// cambia entre nightlies, así que la recompilación tiene que usar **ese**
/// nightly, no «cualquier nightly»; se lee del toml para no fijar la fecha en dos
/// lugares.
fn canal_fijado() -> Option<String> {
    let toml = std::fs::read_to_string(crate_ebpf().join("rust-toolchain.toml")).ok()?;
    toml.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("channel"))
        .and_then(|rest| rest.split('"').nth(1))
        .map(str::to_string)
}

/// `bpf-linker` 0.13.0 en el PATH: es el enlazador del target BPF, y la versión
/// cuenta porque otra puede dar un ELF distinto desde la misma fuente y romper la
/// correspondencia byte a byte.
fn hay_bpf_linker_fijado() -> bool {
    Command::new("bpf-linker")
        .arg("--version")
        .output()
        .is_ok_and(|s| s.status.success() && String::from_utf8_lossy(&s.stdout).contains("0.13.0"))
}

/// El nightly fijado, instalado y con `rust-src`: el target BPF compila `core`
/// desde la fuente, que sólo nightly con ese componente permite.
fn hay_nightly_fijado_con_rust_src(canal: &str) -> bool {
    let Ok(salida) = Command::new("rustc")
        .arg(format!("+{canal}"))
        .args(["--print", "sysroot"])
        // `cargo test` corre con `RUSTUP_TOOLCHAIN` fijado al toolchain de la
        // suite (estable); hay que soltarlo para que el `+<canal>` mande.
        .env_remove("RUSTUP_TOOLCHAIN")
        .output()
    else {
        return false;
    };
    if !salida.status.success() {
        return false;
    }
    let sysroot = String::from_utf8_lossy(&salida.stdout).trim().to_string();
    Path::new(&sysroot)
        .join("lib/rustlib/src/rust/library/core/src/lib.rs")
        .exists()
}

#[test]
fn el_objeto_commiteado_corresponde_a_la_fuente() {
    let Some(canal) = canal_fijado() else {
        eprintln!(
            "no se pudo leer el canal del rust-toolchain.toml del crate BPF; \
             se salta la correspondencia del objeto"
        );
        return;
    };
    if !hay_bpf_linker_fijado() || !hay_nightly_fijado_con_rust_src(&canal) {
        eprintln!(
            "falta el toolchain BPF fijado ({canal} con rust-src y/o bpf-linker 0.13.0); \
             se salta la correspondencia del objeto"
        );
        return;
    }

    // `cargo` pelado desde el dir del crate: rustup lee el pin del
    // `rust-toolchain.toml` (el mismo nightly que usa `build.sh`), no «cualquier
    // nightly». Se suelta `RUSTUP_TOOLCHAIN`, que `cargo test` deja fijado al
    // estable de la suite y que, si queda, pisaría el pin del toml.
    let estado = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .current_dir(crate_ebpf())
        // Se sueltan las variables que cambiarían el build y romperían la
        // comparación byte a byte aunque fuente y objeto coincidan:
        // `RUSTUP_TOOLCHAIN` (lo fija `cargo test`, pisaría el pin), `RUSTFLAGS`/
        // `CARGO_ENCODED_RUSTFLAGS` (reemplazan los rustflags del
        // `.cargo/config.toml` y perderían `-C link-arg=--btf`), y
        // `CARGO_TARGET_DIR` (movería la salida que después se lee).
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .expect("no se pudo lanzar cargo para recompilar firewall-ebpf");
    assert!(
        estado.success(),
        "la recompilación de firewall-ebpf falló; el toolchain está pero el build no salió"
    );

    let commiteado =
        std::fs::read(objeto_commiteado()).expect("no se pudo leer el objeto commiteado");
    let recien =
        std::fs::read(objeto_recompilado()).expect("no se pudo leer el objeto recompilado");

    assert_eq!(
        commiteado, recien,
        "el objeto BPF commiteado no corresponde a firewall-ebpf/src/main.rs. \
         Regeneralo con `firewall-ebpf/build.sh` y commiteá el resultado"
    );
}

/// El objeto commiteado trae el mapa `EVENTS` (ring buffer del mapa en vivo, M1)
/// además de `BLOCKED` y los dos programas. Corre sin toolchain BPF, a diferencia
/// de la correspondencia byte a byte: si alguien deja un objeto viejo (1664 B, sin
/// ring) el daemon fallaría al tomar `EVENTS` en silencio y el mapa quedaría vacío.
#[test]
fn el_objeto_commiteado_trae_el_ring_buffer_de_eventos() {
    let objeto = std::fs::read(objeto_commiteado()).expect("no se pudo leer el objeto");
    let contiene = |n: &str| objeto.windows(n.len()).any(|w| w == n.as_bytes());
    for nombre in ["EVENTS", "BLOCKED", "DOMAIN_BLOCKED", "connect4", "connect6"] {
        assert!(
            contiene(nombre),
            "el objeto BPF commiteado no trae «{nombre}»"
        );
    }
}
