import { useConfigStore } from '@vasakgroup/plugin-config-manager';
import { createPinia, type Store } from 'pinia';
import { createApp } from 'vue';
import App from '@/App.vue';
import { disableNativeContextMenu } from '@/tools/native-menu';
import '@/assets/main.css';

/**
 * Los valores que la especificación de CSP informa en lugar de una URL.
 *
 * Van tal cual: no son rutas y recortarlos los volvería ilegibles.
 */
const MARCADORES_CSP = new Set([
	'inline',
	'eval',
	'wasm-eval',
	'data',
	'blob',
	'filesystem',
	'self',
	'unsafe-eval',
	'unsafe-inline',
]);

/**
 * Saca de una URL lo que no debería quedar en un registro.
 *
 * Se conserva el esquema y la autoridad usando `href`, y no `origin + pathname`:
 * para esquemas propios como `asset:` o `ipc:` el `origin` es la cadena «null»,
 * así que esa forma escribía `null/ruta` y perdía justamente lo que permite
 * entender qué se bloqueó.
 *
 * El caso que faltaba cubrir es el del `catch`: una ruta relativa o
 * protocol-relative hace que `new URL` falle, y devolverla tal cual dejaba la
 * query y el fragmento en el registro — o sea, exactamente lo que esta función
 * viene a evitar. Ahora sólo pasan sin tocar los marcadores de la
 * especificación; cualquier otra cosa se corta antes de `?` o `#`.
 */
const sanearUrl = (valor: string | null | undefined): string => {
	if (!valor) {
		return '';
	}
	try {
		const url = new URL(valor);
		if (url.protocol === 'data:') {
			return 'data:(recortado)';
		}
		// Credenciales, query y fragmento: ahí es donde viajan los tokens.
		url.username = '';
		url.password = '';
		url.search = '';
		url.hash = '';
		return url.href;
	} catch {
		if (MARCADORES_CSP.has(valor)) {
			return valor;
		}
		return valor.split(/[?#]/)[0];
	}
};

// Una violación de CSP no se ve: el recurso no carga y la interfaz queda a
// medias sin decir nada. Se sanean **las dos** URLs, porque `sourceFile` también
// puede llevar query con datos sensibles.
document.addEventListener('securitypolicyviolation', (evento) => {
	// El respaldo se decide antes de sanear: `sanearUrl` nunca devuelve vacío
	// para una entrada con contenido, así que un `|| 'documento'` después de
	// llamarla era código muerto.
	const recurso = evento.blockedURI ? sanearUrl(evento.blockedURI) : '(en línea)';
	const origen = evento.sourceFile ? sanearUrl(evento.sourceFile) : 'documento';
	console.error(
		`[CSP] bloqueado ${recurso} por la directiva ` +
			`«${evento.violatedDirective}» en ${origen}:${evento.lineNumber}`
	);
});

/** Cuánto se espera a los colores antes de montar. */
const PLAZO_CONFIGURACION_MS = 1500;

disableNativeContextMenu();

const app = createApp(App);
const pinia = createPinia();

app.use(pinia);

// Los colores llegan por la configuración, como en el resto del escritorio, y
// acá nadie los pedía: el diálogo salía con la paleta clara por omisión aunque
// la sesión estuviera en oscuro. Se ve enseguida, porque este diálogo aparece
// encima de lo que sea que estés haciendo.
//
// Antes de montar, y con plazo: esta ventana se abre de golpe y se responde en
// dos segundos, así que un destello en claro y después el cambio se ve peor que
// la espera. Si la configuración no contesta, con los colores por omisión sigue
// siendo un diálogo usable; lo que no puede es no aparecer.
// `loadConfig` va en el cuarto parámetro, que es el de las acciones: metida en
// el segundo —el del estado— la aserción esconde su firma real y `vue-tsc` deja
// de comprobar la llamada.
const configuracion = useConfigStore() as unknown as Store<
	'config',
	{ config: unknown },
	Record<string, never>,
	{ loadConfig: () => Promise<void> }
>;

await Promise.race([
	configuracion.loadConfig().catch((error: unknown) => {
		console.error('No se pudo cargar la configuración', error);
	}),
	new Promise((resolve) => setTimeout(resolve, PLAZO_CONFIGURACION_MS)),
]);

app.mount('#app');
