<script setup lang="ts">
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { RESOURCE_TEXT } from '@/resources';
import type { Question } from '@/types/permissions';

const question = ref<Question | null>(null);
const answering = ref(false);
let unlistenFocus: (() => void) | null = null;

/**
 * The window is reused between questions, so what it shows has to be read
 * again each time it appears rather than only on first mount.
 */
const load = async () => {
	question.value = await invoke<Question | null>('pending_request');
};

/** The permission service knows exactly who is asking and what for. */
const permission = computed(() => (question.value?.kind === 'permission' ? question.value : null));

/**
 * The portal knows neither, and hands over prose instead. Kept apart from the
 * case above rather than merged: presenting a portal request as if the program
 * had been identified would be a claim we cannot make.
 */
const portal = computed(() => (question.value?.kind === 'portal' ? question.value : null));

const resourceText = computed(() =>
	permission.value ? (RESOURCE_TEXT[permission.value.resource_id] ?? null) : null
);

const title = computed(() => {
	if (portal.value) return portal.value.title;
	if (!permission.value || !resourceText.value) return '';
	return resourceText.value.title.replace('{0}', permission.value.application.display_name);
});

const explanation = computed(() => {
	if (portal.value) return portal.value.subtitle || portal.value.body;
	return resourceText.value?.explanation ?? '';
});

const answer = async (allowed: boolean) => {
	if (answering.value) return;
	answering.value = true;
	try {
		await invoke('answer', { allowed });
	} finally {
		answering.value = false;
		question.value = null;
	}
};

onMounted(async () => {
	await load();
	// Reloading on focus is what makes a second question appear correctly in
	// the same reused window.
	unlistenFocus = await getCurrentWindow().onFocusChanged(({ payload }) => {
		if (payload) void load();
	});
});

onUnmounted(() => unlistenFocus?.());
</script>

<template>
	<div
		class="h-screen w-screen select-none rounded-corner-window border border-ui-border bg-ui-bg/95 p-6 flex flex-col gap-4"
	>
		<template v-if="title">
			<div class="flex flex-col gap-2">
				<h1 class="text-lg font-semibold text-tx-main">{{ title }}</h1>
				<p v-if="explanation" class="text-sm text-tx-muted">{{ explanation }}</p>
			</div>

			<p v-if="portal && portal.body && portal.subtitle" class="text-sm text-tx-main">
				{{ portal.body }}
			</p>
			<p v-else-if="permission && permission.detail" class="text-sm text-tx-main">
				{{ permission.detail }}
			</p>

			<template v-if="permission">
				<!-- The user is deciding based on which program is asking, so being
				     honest about how sure we are is the point, not a detail. -->
				<p
					v-if="permission.application.provenance === 'unverified'"
					class="rounded-corner border border-status-warning/40 bg-status-warning/10 p-2 text-xs text-status-warning"
				>
					Este programa no está instalado por el sistema, así que no podemos
					garantizar que siga siendo el mismo más adelante.
					<span class="mt-1 block break-all opacity-80">
						{{ permission.application.binary_path }}
					</span>
				</p>
				<p v-else class="break-all text-xs text-tx-muted">
					{{ permission.application.binary_path }}
				</p>
			</template>

			<!-- Nothing to name: the portal passes an app_id that is empty for
			     anything outside a sandbox, which is nearly everything here. -->
			<p v-else-if="portal" class="text-xs text-tx-muted">
				<span v-if="portal.app_id">{{ portal.app_id }}</span>
				<span v-else>
					No podemos confirmar qué programa lo está pidiendo: la solicitud llega
					a través del portal del escritorio, que no lo identifica.
				</span>
			</p>

			<div class="mt-auto flex justify-end gap-2">
				<!-- Refusing is the default action: it is the reversible one, and
				     the safe answer for someone who is not sure. -->
				<button
					type="button"
					:disabled="answering"
					autofocus
					class="rounded-corner border border-ui-border px-4 py-2 text-sm text-tx-main hover:bg-ui-surface disabled:opacity-50"
					@click="answer(false)"
				>
					No permitir
				</button>
				<button
					type="button"
					:disabled="answering"
					class="rounded-corner bg-primary px-4 py-2 text-sm font-semibold text-tx-on-primary hover:bg-secondary disabled:opacity-50"
					@click="answer(true)"
				>
					Permitir
				</button>
			</div>
		</template>

		<p v-else class="m-auto text-sm text-tx-muted">Sin consultas pendientes</p>
	</div>
</template>
