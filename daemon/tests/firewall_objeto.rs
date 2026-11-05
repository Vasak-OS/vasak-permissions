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

/// `bpf-linker` en el PATH: es el enlazador del target BPF.
fn hay_bpf_linker() -> bool {
    Command::new("bpf-linker")
        .arg("--version")
        .output()
        .is_ok_and(|s| s.status.success())
}

/// Nightly instalado y con `rust-src`: el target BPF compila `core` desde la
/// fuente, que sólo nightly con ese componente permite.
fn hay_nightly_con_rust_src() -> bool {
    let Ok(salida) = Command::new("rustc")
        .args(["+nightly", "--print", "sysroot"])
        // `cargo test` corre con `RUSTUP_TOOLCHAIN` fijado al toolchain de la
        // suite (estable); hay que soltarlo para que `+nightly` mande.
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
    if !hay_bpf_linker() || !hay_nightly_con_rust_src() {
        eprintln!(
            "falta el toolchain BPF (nightly con rust-src y/o bpf-linker); \
             se salta la correspondencia del objeto"
        );
        return;
    }

    // `cargo test` deja `RUSTUP_TOOLCHAIN` fijado al estable de la suite, que
    // pisaría el `rust-toolchain.toml` del crate BPF; se suelta y se pide
    // `+nightly` explícito para que el target BPF compile.
    let estado = Command::new("cargo")
        .arg("+nightly")
        .arg("build")
        .arg("--release")
        .current_dir(crate_ebpf())
        .env_remove("RUSTUP_TOOLCHAIN")
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
