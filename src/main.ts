import { createPinia } from 'pinia';
import { createApp } from 'vue';
import App from '@/App.vue';
import { disableNativeContextMenu } from '@/tools/native-menu';
import '@/assets/main.css';

disableNativeContextMenu();

const app = createApp(App);
const pinia = createPinia();

app.use(pinia);

app.mount('#app');
