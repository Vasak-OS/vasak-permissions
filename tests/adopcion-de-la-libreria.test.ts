/**
 * Lo que el diálogo de permisos dejó de dibujar por su cuenta.
 *
 * Dos cosas. Una es un archivo muerto: `useReactiveIcon.ts`, noventa y una
 * líneas que **no importaba nadie** —quedaron de antes de que el marco saliera
 * de la librería, y desde entonces el diálogo no dibuja ningún icono propio—.
 * Un archivo que no se usa no falla, y por eso se queda: nadie tropieza con él.
 *
 * La otra es el aviso de que el programa que pide no está verificado. Traía una
 * copia a mano del borde y el fondo del sistema, y ningún icono.
 *
 * Ésta es la pantalla donde se decide si un programa puede prender la cámara,
 * así que el aviso de «no sabemos de quién es este binario» es lo que más tiene
 * que mirarse. De ahí el icono: es lo que hace mirar.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { AlertMessage, CLASES_POR_TONO, olvidarLosIconosDelTema } from '@vasakgroup/vue-libvasak';
import { mount, type VueWrapper } from '@vue/test-utils';
import App from '@/App.vue';
import { contestar, olvidarTodo } from './dobles';

const RAIZ = new URL('..', import.meta.url).pathname;

let vista: VueWrapper | null = null;

/** El diálogo con una pregunta puesta, como lo abre el servicio. */
async function preguntar(provenance: 'verified' | 'unverified') {
	contestar('pending_request', {
		kind: 'permission',
		resource_id: 'camera',
		detail: '/usr/bin/cheese',
		application: {
			display_name: 'Cheese',
			binary_path: '/usr/bin/cheese',
			provenance,
		},
	});
	vista = mount(App);
	// `onMounted` pide la pregunta con un `await`, así que no está puesta
	// todavía cuando `mount` vuelve.
	await Promise.resolve();
	await Promise.resolve();
	await vista.vm.$nextTick();
	return vista;
}

beforeEach(() => olvidarTodo());

afterEach(() => {
	vista?.unmount();
	vista = null;
	olvidarLosIconosDelTema();
});

describe('el aviso de binario sin verificar', () => {
	test('sale en el aviso del sistema, con su tono', async () => {
		const abierto = await preguntar('unverified');

		const aviso = abierto.findComponent(AlertMessage);
		expect(aviso.exists()).toBe(true);
		expect(aviso.props('tone')).toBe('warning');
		expect(aviso.classes().join(' ')).toContain(CLASES_POR_TONO.warning.split(' ')[0]);
	});

	test('y con icono, que es lo que hace mirar', async () => {
		// Es la ganancia del cambio y por eso se comprueba: sacar el `icon`
		// dejaba el aviso igual de correcto y sin lo único que hace que alguien
		// levante la vista antes de darle la cámara a un programa sin firmar.
		//
		// Se mira la propiedad **y** que el icono llegue al DOM. Lo segundo no
		// comprueba que el nombre exista en el tema de verdad —el doble resuelve
		// cualquier nombre—, sino que la cadena entera funcione: que el aviso lo
		// pase, que `ThemeIcon` lo resuelva y que termine dibujando un `img`.
		// Hay que esperar porque hasta que la resolución vuelve deja un hueco.
		const abierto = await preguntar('unverified');
		const aviso = abierto.findComponent(AlertMessage);

		expect(aviso.props('icon')).toBe('dialog-warning');

		await new Promise((listo) => setTimeout(listo, 0));
		await abierto.vm.$nextTick();

		expect(aviso.find('img').exists()).toBe(true);
	});

	test('dice la ruta, que es lo único que identifica al programa', async () => {
		// Sin nombre verificado, la ruta del binario es el único dato con el que
		// alguien puede decidir. Si se perdiera al mudar el aviso, la pregunta
		// quedaría sin sujeto.
		const abierto = await preguntar('unverified');

		expect(abierto.findComponent(AlertMessage).text()).toContain('/usr/bin/cheese');
	});

	test('y con un programa verificado no aparece', async () => {
		const abierto = await preguntar('verified');

		expect(abierto.findComponent(AlertMessage).exists()).toBe(false);
	});
});

describe('lo que el diálogo ya no tiene', () => {
	test('el composable del icono se fue, y no lo usaba nadie', async () => {
		expect(await Bun.file(`${RAIZ}src/composables/useReactiveIcon.ts`).exists()).toBe(false);
	});

	test('y nadie lo importa', async () => {
		const fuentes = [...new Bun.Glob('src/**/*.{vue,ts}').scanSync(RAIZ)];
		expect(fuentes.length).toBeGreaterThan(5);

		const culpables: string[] = [];
		for (const ruta of fuentes) {
			const texto = await Bun.file(`${RAIZ}${ruta}`).text();
			if (/useReactiveIcon/.test(texto)) culpables.push(ruta);
		}

		expect(culpables).toEqual([]);
	});
});
