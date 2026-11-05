#!/usr/bin/env bash
# Regenera el objeto BPF commiteado del cortafuegos por aplicación.
#
# Requisitos, FIJADOS para que el objeto sea reproducible byte a byte (lo exige
# la prueba de correspondencia): el nightly de `rust-toolchain.toml`
# (`nightly-2026-11-04`) con el componente `rust-src`, y `bpf-linker` 0.13.0
# (`cargo install bpf-linker@0.13.0`). El build estable del daemon NO necesita
# nada de esto: carga el objeto que este script deja commiteado. Al cambiar
# cualquiera de estas versiones, regenerá el objeto en el mismo PR.
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
