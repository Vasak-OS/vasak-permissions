//! El orden del arranque, que es el arreglo.
//!
//! Esto se mira sobre el texto de `lib.rs` y no sobre el programa corriendo
//! porque lo que hay que sostener es un **orden entre dos líneas**, y no hay
//! tipo de Rust que lo ate: mover la toma del nombre de vuelta adentro de
//! `setup()` compila igual, pasa todas las demás pruebas, y sólo se nota al
//! iniciar sesión, como quince segundos de escritorio que no aparece.

const LIB: &str = include_str!("../src/lib.rs");

fn donde(aguja: &str) -> usize {
    LIB.find(aguja).unwrap_or_else(|| {
        panic!(
            "no aparece «{aguja}» en lib.rs. Si se renombró, hay que actualizar \
             esta prueba; si se borró, leer lo que dice abajo antes de borrarla."
        )
    })
}

/// El arreglo, en una línea.
///
/// Construir Tauri inicializa GTK, y `GtkApplication` sondea el gestor de
/// sesión, lo que activa `xdg-desktop-portal` y bloquea. El portal no termina de
/// arrancar hasta encontrar el backend de `org.freedesktop.impl.portal.Access`,
/// que es este proceso. Si el nombre se toma después, los dos se esperan hasta
/// que systemd mata al portal a los quince segundos.
#[test]
fn el_backend_del_portal_toma_su_nombre_antes_de_construir_tauri() {
    assert!(
        donde("portal::serve") < donde("tauri::Builder::default()"),
        "el nombre del portal se toma después de construir Tauri: eso es el \
         abrazo mortal de vuelta, y son quince segundos en cada inicio de sesión"
    );
}

/// El mismo orden, dicho del otro lado: `setup` corre **adentro** de `build()`,
/// así que publicar el backend desde ahí es publicarlo tarde.
#[test]
fn el_backend_no_se_publica_desde_setup() {
    assert!(
        donde("portal::serve") < donde(".setup("),
        "el backend del portal volvió a publicarse desde `setup`, que Tauri corre \
         adentro de `build()` y por lo tanto después de inicializar GTK"
    );
}

/// Y la contracara: un pedido que llegó durante el arranque se despierta en el
/// momento en que se llena el hueco, así que para entonces el estado del
/// diálogo tiene que existir o el pedido no encuentra dónde dibujar.
#[test]
fn el_estado_del_dialogo_existe_antes_de_mostrar_la_aplicacion() {
    assert!(
        donde("DialogState::default()") < donde("cuando.llenar("),
        "se le muestra la aplicación al backend del portal antes de publicar el \
         estado del diálogo: un pedido que estaba esperando se despierta sin él"
    );
}
