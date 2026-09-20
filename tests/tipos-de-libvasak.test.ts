/**
 * Que ningún archivo del repositorio tape los tipos de la librería.
 *
 * `vue-libvasak` publica sus tipos generados en `dist/types/index.d.ts` y los
 * declara en `exports.types`. Dos formas de taparlos, las dos vistas en este
 * ecosistema:
 *
 *  1. un `declare module '@vasakgroup/…'` escrito a mano. Un `declare module`
 *     de un paquete instalado **gana siempre**, así que lo que diga ese archivo
 *     es lo único que se comprueba. En vasak-gallery describía un `WindowFrame`
 *     con `title`/`image`, sin ranuras y con `[key: string]: any` en todo;
 *
 *  2. un `declare module '*.vue'` en `vite-env.d.ts`, herencia de cuando el
 *     chequeo lo hacía `tsc` a secas. `vue-tsc` entiende los `.vue` de forma
 *     nativa y no lo necesita.
 *
 * **Lo que el comodín hace hoy: nada.** Es una declaración *ambiente*, y esas
 * se aplican sólo cuando TypeScript no encuentra un `.d.ts` para el import.
 * Desde la 0.4 la librería publica uno por componente
 * —`dist/types/window/WindowFrame.vue.d.ts`—, así que no llega a aplicarse. Se
 * comprobó metiendo un error de tipo a propósito con el comodín puesto y sin
 * él: salta en los dos casos, tanto sobre un componente de la librería como
 * sobre uno propio.
 *
 * Se saca igual porque es una trampa armada: el día que la librería publique un
 * componente sin su `.d.ts` —o que este repositorio vuelva a una versión que no
 * los genera—, el comodín se aplica y el chequeo deja de mirar sin que nada
 * avise. Eso ya pasó en vasak-desktop, que estaba en la línea 0.2.
 *
 * Las dos primeras pruebas vigilan que ninguna de las dos declaraciones vuelva.
 * La última comprueba lo que de verdad importa —que pasarle algo mal a la
 * librería falle— y no da por hecho que no haya una tercera forma de taparlos.
 */

import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';

// `fileURLToPath` y no `.pathname`: éste deja los caracteres escapados, así que
// un checkout en una ruta con espacios mandaría a `Bun.Glob`, `Bun.file` y
// `Bun.spawn` a una carpeta que no existe.
const raiz = fileURLToPath(new URL('..', import.meta.url));

const fuentes = await Array.fromAsync(new Bun.Glob('src/**/*.{ts,d.ts,vue}').scan({ cwd: raiz }));

async function conteniendo(patron: RegExp): Promise<string[]> {
	const hallados: string[] = [];
	for (const ruta of fuentes) {
		if (patron.test(await Bun.file(`${raiz}${ruta}`).text())) hallados.push(ruta);
	}
	return hallados.sort();
}

/** Corre el chequeo sobre un proyecto suelto y devuelve su salida. */
async function chequear(tsconfig: string): Promise<{ codigo: number; salida: string }> {
	const proceso = Bun.spawn(['bunx', 'vue-tsc', '--noEmit', '-p', tsconfig], {
		cwd: raiz,
		stdout: 'pipe',
		stderr: 'pipe',
	});
	const salida = `${await new Response(proceso.stdout).text()}${await new Response(proceso.stderr).text()}`;
	return { codigo: await proceso.exited, salida };
}

describe('los tipos de la librería', () => {
	test('y las dos pruebas que siguen miran archivos de verdad', () => {
		// Las dos buscan algo que no tiene que aparecer, así que pasan solas si
		// la lista viene vacía —una `raiz` mal armada y no hay nada que mirar—.
		expect(fuentes).toContain('src/vite-env.d.ts');
		expect(fuentes).toContain('src/main.ts');
		expect(fuentes.length).toBeGreaterThan(3);
	});

	test('no los redeclara ningún archivo de la aplicación', async () => {
		// Cualquier `declare module` de un paquete instalado, no sólo el de
		// `vue-libvasak`: el problema es la forma, y la de al lado
		// (`@vasakgroup/plugin-*`) taparía sus tipos igual.
		expect(await conteniendo(/declare\s+module\s+['"]@vasakgroup\//)).toEqual([]);
	});

	test('no los aplana ningún comodín de .vue', async () => {
		expect(await conteniendo(/declare\s+module\s+['"]\*\.vue['"]/)).toEqual([]);
	});

	test('vienen de una versión que los genera', async () => {
		// Hasta la 0.2.x el paquete apuntaba `types` a una declaración escrita a
		// mano; los generados con `vue-tsc` empiezan en la 0.4. Volver a aquella
		// línea deja el chequeo como estaba aunque no vuelva ningún archivo.
		//
		// Se mira la versión instalada y no el rango del manifiesto: es la que
		// se está comprobando, y leerla evita interpretar a mano un `^`, un `~`
		// o un salto de mayor —`^1.0.0` es más nueva que la 0.6 y publica los
		// tipos igual—.
		const instalada = (
			(await Bun.file(`${raiz}node_modules/@vasakgroup/vue-libvasak/package.json`).json()) as {
				version: string;
			}
		).version;

		expect(Bun.semver.satisfies(instalada, '>=0.6.0')).toBe(true);
	});

	test('y se comprueban: el uso correcto pasa', async () => {
		const { codigo, salida } = await chequear('tests/fixtures/tsconfig.json');

		expect(salida).toBe('');
		expect(codigo).toBe(0);
	}, 120_000);

	test.each([
		['una propiedad con el tipo cambiado', ':title="\'Escritorio\'"', ':title="42"'],
		['una bandera que no es booleana', ':hide-bar="false"', ':hide-bar="\'no\'"'],
		[
			'un componente que no existe',
			'import { WindowFrame }',
			'import { WindowFrame, NoExiste }',
		],
	])('y se comprueban: %s falla', async (_caso, busca, pone) => {
		const fuente = await Bun.file(`${raiz}tests/fixtures/UsoDeLaLibreria.vue`).text();
		// Si la sustitución no encuentra nada se estaría comprobando el fixture
		// bueno, que pasa: la prueba mentiría diciendo que el chequeo no tiene
		// dientes cuando el error está acá.
		expect(fuente).toContain(busca);

		const carpeta = `${raiz}tests/fixtures/.sabotaje-${Bun.randomUUIDv7()}`;
		try {
			await Bun.write(`${carpeta}/UsoDeLaLibreria.vue`, fuente.replace(busca, pone));
			await Bun.write(
				`${carpeta}/tsconfig.json`,
				await Bun.file(`${raiz}tests/fixtures/tsconfig.json`).text(),
			);

			const { codigo, salida } = await chequear(
				`tests/fixtures/${carpeta.split('/').pop()}/tsconfig.json`,
			);

			// En el componente y con posición: un tsconfig que no mire nada
			// también termina con error —«No inputs were found»—, y daría por
			// buena la prueba sin haber comprobado el uso.
			expect(salida).toMatch(/UsoDeLaLibreria\.vue\(\d+,\d+\): error TS\d+/);
			expect(codigo).not.toBe(0);
		} finally {
			await Bun.$`rm -rf ${carpeta}`.quiet();
		}
	}, 120_000);
});
