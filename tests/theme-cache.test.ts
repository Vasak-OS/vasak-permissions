import { describe, expect, test } from 'bun:test';
import { applyTheme, saveTheme, THEME_KEY } from '../src/tools/theme-cache';

/** Un `Storage` mínimo en memoria, para no tocar el `localStorage` global. */
function memoryStorage(): Storage {
	const data = new Map<string, string>();
	return {
		get length() {
			return data.size;
		},
		clear: () => data.clear(),
		getItem: (key) => data.get(key) ?? null,
		key: (index) => [...data.keys()][index] ?? null,
		removeItem: (key) => void data.delete(key),
		setItem: (key, value) => void data.set(key, String(value)),
	};
}

/** Un `Storage` que tira en cada acceso, como un `localStorage` bloqueado. */
function brokenStorage(): Storage {
	const fail = () => {
		throw new Error('storage bloqueado');
	};
	return {
		length: 0,
		clear: fail,
		getItem: fail,
		key: fail,
		removeItem: fail,
		setItem: fail,
	};
}

describe('theme-cache', () => {
	test('la clave es la misma que lee el script del index.html', () => {
		expect(THEME_KEY).toBe('vsk-theme');
	});

	test('saveTheme guarda la clase oscura y sólo las variables --*', () => {
		const root = document.createElement('div');
		const storage = memoryStorage();
		root.classList.add('dark');
		root.style.setProperty('--ui-background', '#101010');
		root.style.setProperty('color', 'red');

		saveTheme(root, storage);

		expect(JSON.parse(storage.getItem(THEME_KEY) as string)).toEqual({
			dark: true,
			vars: { '--ui-background': '#101010' },
		});
	});

	test('applyTheme reaplica la clase oscura y las variables', () => {
		const storage = memoryStorage();
		storage.setItem(THEME_KEY, JSON.stringify({ dark: true, vars: { '--primary': '#abcdef' } }));
		const root = document.createElement('div');

		applyTheme(root, storage);

		expect(root.classList.contains('dark')).toBe(true);
		expect(root.style.getPropertyValue('--primary')).toBe('#abcdef');
	});

	test('ida y vuelta: lo guardado de un elemento se reaplica en otro', () => {
		const storage = memoryStorage();
		const first = document.createElement('div');
		first.classList.add('dark');
		first.style.setProperty('--ui-surface', '#222222');
		saveTheme(first, storage);

		const second = document.createElement('div');
		applyTheme(second, storage);

		expect(second.classList.contains('dark')).toBe(true);
		expect(second.style.getPropertyValue('--ui-surface')).toBe('#222222');
	});

	test('un tema claro no agrega la clase oscura', () => {
		const storage = memoryStorage();
		saveTheme(document.createElement('div'), storage);
		const root = document.createElement('div');

		applyTheme(root, storage);

		expect(root.classList.contains('dark')).toBe(false);
	});

	test('sin clave guardada, applyTheme no hace nada', () => {
		const root = document.createElement('div');

		applyTheme(root, memoryStorage());

		expect(root.className).toBe('');
		expect(root.getAttribute('style')).toBeNull();
	});

	test('con JSON inválido no lanza ni toca la raíz', () => {
		const storage = memoryStorage();
		storage.setItem(THEME_KEY, '{no es json');
		const root = document.createElement('div');

		expect(() => applyTheme(root, storage)).not.toThrow();
		expect(root.className).toBe('');
	});

	test('con un Storage que tira, ninguna de las dos lanza', () => {
		const root = document.createElement('div');

		expect(() => saveTheme(root, brokenStorage())).not.toThrow();
		expect(() => applyTheme(root, brokenStorage())).not.toThrow();
	});
});

describe('cableado del tema recordado', () => {
	test('index.html reaplica el tema antes de montar', async () => {
		const html = await Bun.file('index.html').text();
		const script = html.indexOf("localStorage.getItem(\"vsk-theme\"");
		expect(script).toBeGreaterThan(-1);
		expect(html).toContain('classList.add("dark")');
		expect(html).toContain('setProperty(');
		// El script va antes del módulo que monta Vue.
		expect(script).toBeLessThan(html.indexOf('<script type="module"'));
	});

	test('main.ts guarda el tema tras loadConfig', async () => {
		const main = await Bun.file('src/main.ts').text();
		expect(main).toContain("from '@/tools/theme-cache'");
		expect(main).toMatch(/loadConfig\(\)\s*\.then\(\(\) => saveTheme\(\)\)/);
	});
});
