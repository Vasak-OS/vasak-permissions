/**
 * Lo que el diálogo de permisos dejó de dibujar por su cuenta.
 *
 * Tres cosas. Una es un archivo muerto: `useReactiveIcon.ts`, noventa y una
 * líneas que **no importaba nadie** —quedaron de antes de que el marco saliera
 * de la librería, y desde entonces el diálogo no dibuja ningún icono propio—.
 * Un archivo que no se usa no falla, y por eso se queda: nadie tropieza con él.
 *
 * La otra es el aviso de que el programa que pide no está verificado. Traía una
 * copia a mano del borde y el fondo del sistema, y ningún icono.
 *
 * Y los dos botones de contestar, que eran dos `<button>` con el radio, el
 * borde y el relleno escritos a mano —el de «Permitir» pasaba a `bg-secondary`
 * al apuntarlo—. Ahora son el `ActionButton` de la librería.
 *
 * Ésta es la pantalla donde se decide si un programa puede prender la cámara,
 * así que el aviso de «no sabemos de quién es este binario» es lo que más tiene
 * que mirarse. De ahí el icono: es lo que hace mirar.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { ActionButton, AlertMessage, TONE_CLASSES, olvidarLosIconosDelTema } from '@vasakgroup/vue-libvasak';
import { mount, type VueWrapper } from '@vue/test-utils';
import App from '@/App.vue';
import { contestar, invocaciones, olvidarTodo } from './dobles';

const ROOT = new URL('..', import.meta.url).pathname;

let view: VueWrapper | null = null;

/** El diálogo con una pregunta puesta, como lo abre el servicio. */
async function ask(provenance: 'verified' | 'unverified', options: { attachTo?: Element } = {}) {
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
	view = mount(App, options);
	// `onMounted` pide la pregunta con un `await`, así que no está puesta
	// todavía cuando `mount` vuelve.
	await Promise.resolve();
	await Promise.resolve();
	await view.vm.$nextTick();
	return view;
}

beforeEach(() => olvidarTodo());

afterEach(() => {
	view?.unmount();
	view = null;
	olvidarLosIconosDelTema();
});

describe('el aviso de binario sin verificar', () => {
	test('sale en el aviso del sistema, con su tono', async () => {
		const opened = await ask('unverified');

		const alert = opened.findComponent(AlertMessage);
		expect(alert.exists()).toBe(true);
		expect(alert.props('tone')).toBe('warning');
		expect(alert.classes().join(' ')).toContain(TONE_CLASSES.warning.split(' ')[0]);
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
		const opened = await ask('unverified');
		const alert = opened.findComponent(AlertMessage);

		expect(alert.props('icon')).toBe('dialog-warning');

		await new Promise((done) => setTimeout(done, 0));
		await opened.vm.$nextTick();

		expect(alert.find('img').exists()).toBe(true);
	});

	test('dice la ruta, que es lo único que identifica al programa', async () => {
		// Sin nombre verificado, la ruta del binario es el único dato con el que
		// alguien puede decidir. Si se perdiera al mudar el aviso, la pregunta
		// quedaría sin sujeto.
		const opened = await ask('unverified');

		expect(opened.findComponent(AlertMessage).text()).toContain('/usr/bin/cheese');
	});

	test('y con un programa verificado no aparece', async () => {
		const opened = await ask('verified');

		expect(opened.findComponent(AlertMessage).exists()).toBe(false);
	});
});

describe('los botones de contestar', () => {
	test('son los de la librería, en el orden de siempre', async () => {
		const opened = await ask('verified');

		const buttons = opened.findAllComponents(ActionButton);
		expect(buttons.map((button) => button.props('label'))).toEqual(['dialog.deny', 'dialog.allow']);
		// Ningún `<button>` propio al lado de los de la librería.
		expect(opened.findAll('button')).toHaveLength(2);
	});

	test('negar es la secundaria y permitir la principal', async () => {
		// Al revés, el color de la marca invitaría a dar el permiso.
		const opened = await ask('verified');

		const [deny, allow] = opened.findAllComponents(ActionButton);
		expect(deny?.props('variant')).toBe('secondary');
		expect(allow?.props('variant')).toBe('primary');
	});

	test('el foco arranca en negar, que es la respuesta reversible', async () => {
		const opened = await ask('verified', { attachTo: document.body });
		await opened.vm.$nextTick();

		const [deny] = opened.findAll('button');
		expect(document.activeElement).toBe(deny?.element);
	});

	test('cada uno contesta lo suyo', async () => {
		const opened = await ask('verified');

		await opened.findAll('button')[1]?.trigger('click');
		await Promise.resolve();

		const answers = invocaciones.filter((call) => call.comando === 'answer').map((call) => call.argumentos);
		expect(answers).toEqual([{ allowed: true }]);
	});
});

describe('lo que el diálogo ya no tiene', () => {
	test('el composable del icono se fue, y no lo usaba nadie', async () => {
		expect(await Bun.file(`${ROOT}src/composables/useReactiveIcon.ts`).exists()).toBe(false);
	});

	test('y nadie lo importa', async () => {
		const files = [...new Bun.Glob('src/**/*.{vue,ts}').scanSync(ROOT)];
		expect(files.length).toBeGreaterThan(5);

		const offenders: string[] = [];
		for (const path of files) {
			const text = await Bun.file(`${ROOT}${path}`).text();
			if (/useReactiveIcon/.test(text)) offenders.push(path);
		}

		expect(offenders).toEqual([]);
	});
});
