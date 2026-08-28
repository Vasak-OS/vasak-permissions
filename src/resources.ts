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
export const RECURSOS_CONOCIDOS = [
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
] as const;

export type RecursoConocido = (typeof RECURSOS_CONOCIDOS)[number];

/** Si este id tiene textos en el catálogo. */
export function esRecursoConocido(id: string): id is RecursoConocido {
	return (RECURSOS_CONOCIDOS as readonly string[]).includes(id);
}
