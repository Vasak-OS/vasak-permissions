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
/** Este mismo archivo, relativo a la raíz. */
const propio = fileURLToPath(import.meta.url).slice(raiz.length);

/**
 * Todo lo que el chequeo de tipos mira, no sólo `src`.
 *
 * El `tsconfig` de la raíz incluye también `tests/**` y los `.tsx`, y el de
 * node los archivos de configuración sueltos. Una declaración puesta en
 * cualquiera de esos lugares tapa los tipos igual, y con un patrón más angosto
 * las dos pruebas de abajo pasarían sin haberla visto. Lo marcó la revisión.
 */
const fuentes = (
	await Promise.all(
		['src/**/*.{ts,tsx,mts,cts,vue}', 'tests/**/*.{ts,tsx,vue}', '*.{ts,mts,cts}'].map(
			async (patron) => await Array.fromAsync(new Bun.Glob(patron).scan({ cwd: raiz }))
		)
	)
).flat()
	// Menos este archivo. Los patrones que busca los lleva escritos adentro,
	// así que al ampliar el escaneo a `tests/` empezó a encontrarse a sí mismo.
	.filter((ruta) => ruta !== propio);

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
		// Y que los tres patrones traigan algo: el de `tests` y el de la raíz se
		// sumaron porque el de `src` solo dejaba huecos, y un patrón que no
		// encuentra nada los deja igual.
		expect(fuentes.some((ruta) => ruta.startsWith('tests/'))).toBe(true);
		expect(fuentes).toContain('vite.config.ts');
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

	test('y se comprueban: los dos usos correctos pasan', async () => {
		const { codigo, salida } = await chequear('tests/fixtures/tsconfig.json');

		expect(salida).toBe('');
		expect(codigo).toBe(0);
	}, 120_000);

	// El último caso es sobre un componente **propio** y no de la librería: las
	// dos cosas se rompen por caminos distintos, y sin él una regresión que
	// dejara de mirar lo propio pasaría desapercibida. Lo marcó la revisión.
	test.each([
		['UsoDeLaLibreria.vue', 'una propiedad con el tipo cambiado', ':title="\'Escritorio\'"', ':title="42"'],
		['UsoDeLaLibreria.vue', 'una bandera que no es booleana', ':hide-bar="false"', ':hide-bar="\'no\'"'],
		[
			'UsoDeLaLibreria.vue',
			'un componente que no existe',
			'import { WindowFrame }',
			'import { WindowFrame, NoExiste }',
		],
		['UsoDelPropio.vue', 'una propiedad de un componente propio', ':etiqueta="\'aceptar\'"', ':etiqueta="42"'],
	])('y se comprueban: %s, %s falla', async (archivo, _caso, busca, pone) => {
		const fuente = await Bun.file(`${raiz}tests/fixtures/${archivo}`).text();
		// Si la sustitución no encuentra nada se estaría comprobando el fixture
		// bueno, que pasa: la prueba mentiría diciendo que el chequeo no tiene
		// dientes cuando el error está acá.
		expect(fuente).toContain(busca);

		// La carpeta entera, con el archivo elegido saboteado: los fixtures se
		// importan entre ellos, así que copiar uno solo dejaría el chequeo
		// fallando por un import que no existe en vez de por el tipo.
		// `Bun.write` crea los directorios padre, así que no hace falta `mkdir`.
		const carpeta = `${raiz}tests/fixtures/.sabotaje-${Bun.randomUUIDv7()}`;
		try {
			for (const nombre of [
				'UsoDeLaLibreria.vue',
				'UsoDelPropio.vue',
				'ComponentePropio.vue',
				'tsconfig.json',
			]) {
				await Bun.write(
					`${carpeta}/${nombre}`,
					nombre === archivo
						? fuente.replace(busca, pone)
						: await Bun.file(`${raiz}tests/fixtures/${nombre}`).text(),
				);
			}

			const { codigo, salida } = await chequear(
				`tests/fixtures/${carpeta.split('/').pop()}/tsconfig.json`,
			);

			// En el componente y con posición: un tsconfig que no mire nada
			// también termina con error —«No inputs were found»—, y daría por
			// buena la prueba sin haber comprobado el uso.
			expect(salida).toMatch(new RegExp(`${archivo.replace('.', '\\.')}\\(\\d+,\\d+\\): error TS\\d+`));
			expect(codigo).not.toBe(0);
		} finally {
			await Bun.$`rm -rf ${carpeta}`.quiet();
		}
	}, 120_000);
});

/**
 * El `tsconfig` sin sus comentarios, listo para `JSON.parse`.
 *
 * Es JSONC, así que `.json()` se cae con «Unrecognized token '/'». Y quitar los
 * comentarios con una expresión regular tampoco alcanza: el alias `"@/*"` lleva
 * un `/*` adentro de las comillas, y el quitador se come desde ahí hasta el
 * próximo `*​/`, dejando el JSON partido. Por eso este recorre el texto sabiendo
 * cuándo está dentro de una cadena.
 */
async function leerTsconfig(): Promise<{
	vueCompilerOptions?: { strictTemplates?: boolean };
}> {
	const crudo = await Bun.file(`${raiz}tsconfig.json`).text();
	let salida = '';
	let enCadena = false;
	let escapado = false;
	for (let i = 0; i < crudo.length; i++) {
		const caracter = crudo[i];
		if (enCadena) {
			salida += caracter;
			if (escapado) escapado = false;
			else if (caracter === '\\') escapado = true;
			else if (caracter === '"') enCadena = false;
			continue;
		}
		if (caracter === '"') {
			enCadena = true;
			salida += caracter;
			continue;
		}
		if (caracter === '/' && crudo[i + 1] === '/') {
			while (i < crudo.length && crudo[i] !== '\n') i++;
			salida += '\n';
			continue;
		}
		if (caracter === '/' && crudo[i + 1] === '*') {
			i += 2;
			while (i < crudo.length && !(crudo[i] === '*' && crudo[i + 1] === '/')) i++;
			i++;
			continue;
		}
		salida += caracter;
	}
	return JSON.parse(salida);
}

describe('el chequeo de las plantillas', () => {
	test('mira cada atributo, no sólo los que reconoce', async () => {
		// Sin `strictTemplates`, `vue-tsc` comprueba el tipo de las propiedades
		// que **sí** existen y no dice nada de una que no existe, de un evento
		// que el componente no emite, ni de un atributo inventado sobre un
		// elemento. Un `@click` sobre un componente sin `defineEmits` funciona
		// por caída de atributos y nunca se nota; un `:size` sobre un `<img>` no
		// hace nada y tampoco.
		const tsconfig = await leerTsconfig();

		expect(tsconfig.vueCompilerOptions?.strictTemplates).toBe(true);
	});

	test('y los `data-*` siguen permitidos, que es la excepción legítima', async () => {
		// HTML los permite todos, y acá marcan nodos que después se buscan con
		// `closest()` o `querySelector()`. Declararlos uno por uno deja la lista
		// vieja en cuanto alguien marca un nodo nuevo, así que se declara la
		// forma.
		const declaracion = await Bun.file(`${raiz}src/tipos-de-plantilla.d.ts`).text();

		// Con una expresión regular y no con `toContain`: escrito como cadena,
		// `'data-${string}'` hace que el linter avise de un marcador de
		// plantilla que no se interpola, y no es eso lo que pasa.
		expect(declaracion).toMatch(/\[atributo: `data-\$\{string\}`\]/);
		expect(declaracion).toContain("declare module 'vue'");
	});
});
