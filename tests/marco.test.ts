/**
 * El diálogo dibuja el marco compartido, y sin ningún botón de ventana.
 *
 * Los dos puntos importan por razones distintas. El marco, porque este diálogo
 * aparece encima de cualquier cosa y una esquina distinta a la de la ventana
 * que tiene debajo se ve. Los botones, porque acá la ventana **se responde**:
 * cerrarla dejaría al programa que pidió el permiso esperando para siempre, y
 * la pregunta sin respuesta sin que nadie se entere.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { WindowControls, WindowFrame } from '@vasakgroup/vue-libvasak';
import { mount, type VueWrapper } from '@vue/test-utils';
import App from '@/App.vue';
import { contestar, laVentanaRecibio, olvidarTodo } from './dobles';

let vista: VueWrapper | null = null;

/** Abre el diálogo con una pregunta puesta, como lo abre el servicio. */
async function preguntar() {
	contestar('pending_request', {
		kind: 'permission',
		resource_id: 'camera',
		detail: '/usr/bin/cheese',
		application: {
			display_name: 'Cheese',
			binary_path: '/usr/bin/cheese',
			provenance: 'verified',
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
});

describe('el marco del diálogo', () => {
	test('es el compartido y no uno copiado a mano', async () => {
		const abierto = await preguntar();

		expect(abierto.findComponent(WindowFrame).exists()).toBe(true);
	});

	test('no queda ninguna ventana dibujada a mano', async () => {
		// `rounded-corner-window` es el borde de la ventana: sale del marco
		// compartido y de ningún otro lado. Con dos, la esquina y el fondo se
		// dibujan dos veces y se ven los dos.
		const abierto = await preguntar();

		expect(abierto.findAll('.rounded-corner-window')).toHaveLength(1);
	});
});

describe('los botones de la ventana', () => {
	test('no hay ninguno', async () => {
		// Ni minimizar, ni maximizar, ni cerrar. La única salida es contestar.
		const abierto = await preguntar();

		expect(abierto.findComponent(WindowControls).exists()).toBe(false);
		expect(abierto.findAll('button[aria-label="Close"]')).toHaveLength(0);
	});

	test('y nada le pide a la ventana que se cierre', async () => {
		// Lo que se comprueba no es que no haya botón sino que no haya forma:
		// un `close()` colgado de una tecla o de un clic en el fondo sería el
		// mismo agujero con otra cara.
		const abierto = await preguntar();

		for (const boton of abierto.findAll('button')) await boton.trigger('click');

		expect(laVentanaRecibio).toEqual([]);
	});

	test('los botones que sí hay son los de contestar', async () => {
		const abierto = await preguntar();

		const nombres = abierto.findAll('button').map((boton) => boton.text());
		expect(nombres).toEqual(['dialog.deny', 'dialog.allow']);
	});
});
