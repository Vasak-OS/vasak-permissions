import { useConfigStore } from '@vasakgroup/plugin-config-manager';
import { createPinia } from 'pinia';
import { createApp } from 'vue';
import App from '@/App.vue';
import { sanearUrl } from '@/tools/csp';
import { disableNativeContextMenu } from '@/tools/native-menu';
import '@/assets/main.css';

// Una violación de CSP no se ve: el recurso no carga y la interfaz queda a
// medias sin decir nada. Se sanean **las dos** URLs, porque `sourceFile` también
// puede llevar query con datos sensibles.
document.addEventListener('securitypolicyviolation', (evento) => {
	// El respaldo va **después** de sanear, no antes.
	//
	// Mirando el valor crudo, una entrada como `?token=X` es verdadera y
	// pasa el respaldo de largo — pero lo que queda de ella al sanearla es
	// nada, así que el registro salía con el campo en blanco. Sanear
	// primero y decidir después es lo que hace que un aviso incompleto no
	// exista.
	const recurso = sanearUrl(evento.blockedURI) || '(en línea)';
	const origen = sanearUrl(evento.sourceFile) || 'documento';
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
const configuracion = useConfigStore();

await Promise.race([
	configuracion.loadConfig().catch((error: unknown) => {
		console.error('No se pudo cargar la configuración', error);
	}),
	new Promise((resolve) => setTimeout(resolve, PLAZO_CONFIGURACION_MS)),
]);

app.mount('#app');
