/**
 * Los recursos que el diálogo sabe describir, contra los catálogos de idioma.
 *
 * Son tres listas que no se hablan: los recursos del protocolo, la lista de
 * `src/resources.ts` y los textos de `src-tauri/locales/`. Un recurso que está
 * en el protocolo y no acá deja el diálogo **en blanco** —no arma la clave de un
 * recurso que no conoce—, y uno que está acá sin textos muestra la clave cruda.
 * Las dos cosas pasan en la pantalla donde alguien decide si una aplicación
 * puede leer su correo.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { mount, type VueWrapper } from '@vue/test-utils';
import App from '@/App.vue';
import { isKnownResource, KNOWN_RESOURCES } from '@/resources';
import { contestar, olvidarTodo } from './dobles';

const LANGUAGES = ['es', 'en'] as const;
const STORE_RESOURCES = ['store.email', 'store.calendar', 'store.contacts'];

type Catalog = { resources: Record<string, { title?: string; explanation?: string }> };

function catalog(language: string): Catalog {
	const path = join(import.meta.dir, '..', 'src-tauri', 'locales', `${language}.yml`);
	return Bun.YAML.parse(readFileSync(path, 'utf8')) as Catalog;
}

describe('los recursos que el diálogo conoce', () => {
	test('incluyen los tres del almacén local', () => {
		for (const id of STORE_RESOURCES) {
			expect(KNOWN_RESOURCES as readonly string[]).toContain(id);
			expect(isKnownResource(id)).toBe(true);
		}
	});

	test('un área del almacén inventada no se reconoce', () => {
		for (const id of ['store.algo', 'store.drive', 'store.', 'store']) {
			expect(isKnownResource(id)).toBe(false);
		}
	});

	for (const language of LANGUAGES) {
		test(`cada uno tiene título y explicación en ${language}.yml`, () => {
			const { resources } = catalog(language);
			for (const id of KNOWN_RESOURCES) {
				expect(resources[id]?.title, `${language}.yml: ${id}.title`).toBeString();
				expect(resources[id]?.explanation, `${language}.yml: ${id}.explanation`).toBeString();
				expect(resources[id]?.title).toContain('{0}');
			}
		});

		test(`${language}.yml no tiene textos para un recurso que el diálogo no conoce`, () => {
			// Un texto escrito para un id que no está en la lista no se muestra
			// nunca: el diálogo lo descarta antes de buscarlo.
			const { resources } = catalog(language);
			for (const id of Object.keys(resources)) {
				expect(isKnownResource(id), `${language}.yml: ${id}`).toBe(true);
			}
		});
	}
});

describe('el diálogo ante una lectura del almacén', () => {
	let view: VueWrapper | null = null;

	beforeEach(() => olvidarTodo());

	afterEach(() => {
		view?.unmount();
		view = null;
	});

	test('arma la pregunta con los textos de store.contacts', async () => {
		contestar('pending_request', {
			kind: 'permission',
			resource_id: 'store.contacts',
			detail: '',
			application: {
				display_name: 'Contactos',
				binary_path: '/usr/bin/vasak-contacts',
				provenance: 'system-installed',
			},
		});
		view = mount(App);
		// `onMounted` pide la pregunta con un `await`.
		await Promise.resolve();
		await Promise.resolve();
		await view.vm.$nextTick();

		// El `t()` de las pruebas devuelve la clave, así que ver la clave es ver
		// que el diálogo la armó en vez de quedar en blanco.
		expect(view.text()).toContain('resources.store.contacts.title');
		expect(view.text()).toContain('resources.store.contacts.explanation');
	});
});
