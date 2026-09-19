/**
 * Los dobles de lo que sólo existe adentro de la ventana de Tauri.
 *
 * Montar el diálogo es lo único que comprueba de verdad qué marco dibuja y qué
 * botones lleva; sin estos, importarlo falla en la primera línea.
 */

const respuestas = new Map<string, unknown>();

export const invocaciones: { comando: string; argumentos: unknown }[] = [];

export async function invoke(comando: string, argumentos?: unknown) {
	invocaciones.push({ comando, argumentos });
	return respuestas.get(comando);
}

/** Lo que contesta el backend a un comando. */
export function contestar(comando: string, valor: unknown) {
	respuestas.set(comando, valor);
}

/** El `t()` devuelve la clave: una prueba que mire el texto mira la clave. */
export function useI18n() {
	return { t: (clave: string) => clave, locale: { value: 'es' } };
}

/** Lo que `readConfig()` le devuelve al marco para saber dónde va la barra. */
export async function readConfig() {
	return {};
}

export function useConfigStore() {
	return { config: {}, loadConfig: async () => {} };
}

export const laVentanaRecibio: string[] = [];

export function getCurrentWindow() {
	return {
		minimize: async () => void laVentanaRecibio.push('minimize'),
		toggleMaximize: async () => void laVentanaRecibio.push('toggleMaximize'),
		close: async () => void laVentanaRecibio.push('close'),
		onFocusChanged: async () => () => {},
	};
}

export function olvidarTodo() {
	invocaciones.length = 0;
	respuestas.clear();
	laVentanaRecibio.length = 0;
}

/** El tema de iconos. El marco pide los de los botones de ventana. */
export async function getIconSource(_nombre: string) {
	return '';
}

export async function getSymbolSource(_nombre: string) {
	return '';
}

/** El aviso de que cambió el tema de iconos, que el marco escucha. */
export async function listen(_nombre: string, _manejador: () => unknown) {
	return () => {};
}
