/**
 * Qué recursos sabe describir este diálogo.
 *
 * Los textos viven en el catálogo de idiomas, bajo `resources.<id>`, y no acá:
 * es lo que se le muestra a alguien para decidir si una aplicación puede usar
 * su cámara, y tiene que estar en el idioma de la sesión.
 *
 * Esta lista queda porque hace falta saber si un recurso es conocido: con un id
 * que no está en el catálogo, pedir su texto devolvería la clave cruda —
 * `resources.loquesea.title`— en la pantalla donde menos se puede permitir.
 */
export const KNOWN_RESOURCES = [
	'camera',
	'microphone',
	'screen-capture',
	'location',
	'input-capture',
	'account.email',
	'account.calendar',
	'account.contacts',
	'account.chat',
	'account.drive',
	'account.tasks',
	// Leer lo que el sincronizador guardó en el almacén local. Otra pregunta que
	// la de `account.*`: no llega a la cuenta, sólo a lo que ya se bajó.
	'store.email',
	'store.calendar',
	'store.contacts',
] as const;

export type KnownResource = (typeof KNOWN_RESOURCES)[number];

/** Si este id tiene textos en el catálogo. */
export function isKnownResource(id: string): id is KnownResource {
	return (KNOWN_RESOURCES as readonly string[]).includes(id);
}
