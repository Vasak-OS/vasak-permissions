/**
 * Apaga el menú del clic derecho que dibuja el motor del navegador.
 *
 * WebKit ofrece «Recargar», «Inspeccionar elemento» y «Abrir enlace en una
 * ventana nueva» sobre un diálogo que no es una página web: nada de eso
 * pertenece acá, y recargar es directamente peligroso — deja el diálogo en un
 * estado que nadie pidió mientras del otro lado hay un programa esperando una
 * respuesta sobre un permiso.
 *
 * Este diálogo no pone un menú propio en su lugar, y es a propósito: lo único
 * que se decide acá es permitir o no permitir, y ambas cosas ya son botones.
 * Un menú del clic derecho con acciones sobre una consulta de seguridad sería
 * otra forma de responderla sin haberla leído.
 *
 * Prevenir el comportamiento por defecto no cancela los escuchas de la página,
 * así que si alguna vez hace falta un menú propio, este archivo no lo estorba.
 */
export function disableNativeContextMenu(): void {
	// En captura y sobre el documento: el evento se ataja antes de llegar a
	// cualquier elemento, incluidos los que todavía no existen.
	document.addEventListener('contextmenu', (event) => event.preventDefault(), {
		capture: true,
	});
}
