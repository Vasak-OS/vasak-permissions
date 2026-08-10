/**
 * How each resource is described to a person.
 *
 * Written out per resource rather than generated from the id: "acceder al
 * micrófono" and "usar el correo de tu cuenta" are not the same sentence, and
 * a permission dialog that reads like a database field is one people click
 * through without understanding.
 */
export interface ResourceText {
	/** `{0}` is the program's name. */
	title: string;
	explanation: string;
}

export const RESOURCE_TEXT: Record<string, ResourceText> = {
	camera: {
		title: '¿Querés que {0} use la cámara?',
		explanation: 'Va a poder ver y grabar lo que capte la cámara mientras lo uses.',
	},
	microphone: {
		title: '¿Querés que {0} use el micrófono?',
		explanation: 'Va a poder escuchar y grabar lo que digas mientras lo uses.',
	},
	'screen-capture': {
		title: '¿Querés que {0} vea tu pantalla?',
		explanation:
			'Va a poder ver y grabar todo lo que se muestre, incluidas otras aplicaciones y lo que escribas en ellas.',
	},
	location: {
		title: '¿Querés que {0} sepa dónde estás?',
		explanation: 'Va a poder conocer tu ubicación aproximada.',
	},
	'input-capture': {
		title: '¿Querés que {0} lea el teclado?',
		explanation:
			'Va a poder ver todo lo que escribas, también en otras aplicaciones y también tus contraseñas.',
	},
	'account.email': {
		title: '¿Querés que {0} acceda a tu correo?',
		explanation: 'Va a poder leer y enviar correo desde la cuenta que elijas.',
	},
	'account.calendar': {
		title: '¿Querés que {0} acceda a tu calendario?',
		explanation: 'Va a poder ver y modificar tus eventos.',
	},
	'account.contacts': {
		title: '¿Querés que {0} acceda a tus contactos?',
		explanation: 'Va a poder ver y modificar tu libreta de direcciones.',
	},
	'account.chat': {
		title: '¿Querés que {0} acceda a tus mensajes?',
		explanation: 'Va a poder leer y enviar mensajes desde tu cuenta.',
	},
	'account.drive': {
		title: '¿Querés que {0} acceda a tus archivos en la nube?',
		explanation: 'Va a poder ver, modificar y subir archivos a tu cuenta.',
	},
	'account.tasks': {
		title: '¿Querés que {0} acceda a tus tareas?',
		explanation: 'Va a poder ver y modificar tus listas de tareas.',
	},
};
