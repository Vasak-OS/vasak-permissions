#!/usr/bin/env bash
# Regenera el objeto BPF commiteado del cortafuegos por aplicación.
#
# Requisitos (ya documentados en el PKGBUILD como makedepends): Rust nightly con
# el componente `rust-src` y `bpf-linker` (`cargo install bpf-linker`). El build
# estable del daemon NO necesita nada de esto: carga el objeto que este script
# deja commiteado.
#
# Corré esto cada vez que cambie `src/main.rs`; la prueba de correspondencia del
# daemon (`daemon/tests/firewall_objeto.rs`) falla si el objeto no coincide con
# la fuente.
set -euo pipefail

cd "$(dirname "$0")"

OBJETO_FUENTE="target/bpfel-unknown-none/release/vasak-firewall"
OBJETO_DESTINO="../daemon/src/firewall/vasak-firewall.bpf.o"

cargo +nightly build --release

cp "$OBJETO_FUENTE" "$OBJETO_DESTINO"
echo "Objeto BPF regenerado en $OBJETO_DESTINO"
