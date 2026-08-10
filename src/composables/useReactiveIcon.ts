import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { getIconSource, getSymbolSource } from '@vasakgroup/plugin-vicons';
import { onMounted, onUnmounted, ref, watch, type Ref } from 'vue';

export type IconConfig = string | { name: string; type?: 'icon' | 'symbol' };

let unlisten: UnlistenFn | null = null;
let subscribers = 0;
const themeVersion = ref(0);

function useThemeListener() {
  onMounted(() => {
    subscribers++;
    if (subscribers === 1) {
      listen('vicons:theme-changed', () => {
        themeVersion.value++;
      }).then((fn) => { unlisten = fn; });
    }
  });

  onUnmounted(() => {
    subscribers--;
    if (subscribers <= 0 && unlisten) {
      unlisten();
      unlisten = null;
    }
  });

  return themeVersion;
}

export function useReactiveIcon(fetcher: () => Promise<string>) {
  const source = ref('');
  const version = useThemeListener();
  let id = 0;

  watch(
    version,
    async () => {
      const requestId = ++id;
      try {
        const result = await fetcher();
        if (requestId === id) source.value = result;
      } catch {
        if (requestId === id) source.value = '';
      }
    },
    { immediate: true }
  );

  return source;
}

export function useReactiveIcons<T extends Record<string, IconConfig>>(
  icons: T
): { [K in keyof T]: Ref<string> } {
  const result = {} as { [K in keyof T]: Ref<string> };
  const entries = Object.entries(icons);
  const version = useThemeListener();
  const keyTokens: Record<string, number> = {};

  for (const [key] of entries) {
    (result as Record<string, Ref<string>>)[key] = ref('');
    keyTokens[key] = 0;
  }

  async function refreshAll() {
    for (const [key, config] of entries) {
      const keyId = ++keyTokens[key];
      const resolved =
        typeof config === 'string'
          ? { name: config, type: 'symbol' as const }
          : { name: config.name, type: config.type ?? ('symbol' as const) };

      const src =
        resolved.type === 'icon'
          ? await getIconSource(resolved.name)
          : await getSymbolSource(resolved.name);

      if (keyId === keyTokens[key]) {
        (result as Record<string, Ref<string>>)[key].value = src;
      }
    }
  }

  watch(version, refreshAll, { immediate: true });

  return result;
}
