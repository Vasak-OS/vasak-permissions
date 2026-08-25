import { createPinia } from 'pinia';
import { createApp } from 'vue';
import App from '@/App.vue';
import { disableNativeContextMenu } from '@/tools/native-menu';
import '@/assets/main.css';

/**
 * Saca de una URL lo que no debería quedar en un registro.
 *
 * Se conserva el esquema y la autoridad usando `href`, y no `origin +
 * pathname`: para esquemas propios como `asset:` o `ipc:` el `origin` es la
 * cadena «null», así que esa forma escribía `null/ruta` y perdía justamente lo
 * que permite entender qué se bloqueó.
 */
const sanearUrl = (valor: string | null | undefined): string => {
	if (!valor) {
		return '(en línea)';
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
		// No era una URL absoluta —'inline', 'eval', una ruta relativa—: tal cual.
		return valor;
	}
};

// Una violación de CSP no se ve: el recurso no carga y la interfaz queda a
// medias sin decir nada. Se sanean **las dos** URLs, porque `sourceFile`
// también puede llevar query con datos sensibles.
document.addEventListener('securitypolicyviolation', (evento) => {
	console.error(
		`[CSP] bloqueado ${sanearUrl(evento.blockedURI)} por la directiva ` +
			`«${evento.violatedDirective}» en ${sanearUrl(evento.sourceFile) || 'documento'}:${evento.lineNumber}`
	);
});

disableNativeContextMenu();

const app = createApp(App);
const pinia = createPinia();

app.use(pinia);

app.mount('#app');
