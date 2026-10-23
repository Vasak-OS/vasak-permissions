/**
 * Recordar el tema entre arranques para que la ventana no parpadee.
 *
 * El gestor de configuración aplica el esquema del usuario —las variables `--*`
 * sobre el elemento raíz y la clase `.dark`— recién después de montar, así que la
 * ventana abría con el esquema por defecto de la hoja de estilos y viraba al del
 * usuario con la transición de color de 300 ms. Para evitarlo, se guarda el tema
 * ya aplicado y un script en el `<head>` de `index.html` lo reaplica **antes** de
 * montar, de modo que el primer dibujo ya sea el correcto.
 *
 * Este módulo existe aparte para poder probar la lógica; el script del `<head>`
 * es una copia mínima de [`applyTheme`] porque corre antes del bundle y no puede
 * importar nada.
 */

/** La clave bajo la que vive el tema recordado. La comparte con `index.html`. */
export const THEME_KEY = 'vsk-theme';

/** El tema recordado: la clase oscura y las variables que puso el gestor. */
export interface CachedTheme {
	dark: boolean;
	vars: Record<string, string>;
}

/**
 * Guarda el tema que el gestor de configuración dejó aplicado sobre `root`.
 * No lanza: un `localStorage` inaccesible no debe romper el arranque.
 */
export function saveTheme(
	root: HTMLElement = document.documentElement,
	storage: Storage = localStorage
): void {
	try {
		const vars: Record<string, string> = {};
		for (const name of Array.from(root.style)) {
			if (name.startsWith('--')) vars[name] = root.style.getPropertyValue(name);
		}
		const theme: CachedTheme = { dark: root.classList.contains('dark'), vars };
		storage.setItem(THEME_KEY, JSON.stringify(theme));
	} catch {
		// localStorage puede no estar disponible: sin recuerdo, arranca como antes.
	}
}

/** Reaplica sobre `root` el tema recordado. La usa la prueba; el arranque real lo hace el `<head>`. */
export function applyTheme(
	root: HTMLElement = document.documentElement,
	storage: Storage = localStorage
): void {
	try {
		const raw = storage.getItem(THEME_KEY);
		if (!raw) return;
		const theme = JSON.parse(raw) as CachedTheme;
		if (theme.dark) root.classList.add('dark');
		for (const name in theme.vars) root.style.setProperty(name, theme.vars[name]);
	} catch {
		// Sin recuerdo válido, arranca como antes.
	}
}
