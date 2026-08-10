<script setup lang="ts">
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { RESOURCE_TEXT } from '@/resources';
import type { PermissionRequest } from '@/types/permissions';

const request = ref<PermissionRequest | null>(null);
const answering = ref(false);
let unlistenFocus: (() => void) | null = null;

/**
 * The window is reused between questions, so what it shows has to be read
 * again each time it appears rather than only on first mount.
 */
const load = async () => {
	request.value = await invoke<PermissionRequest | null>('pending_request');
};

const text = computed(() => RESOURCE_TEXT[request.value?.resource_id ?? ''] ?? null);

const title = computed(() => {
	const name = request.value?.application.display_name ?? '';
	return text.value ? text.value.title.replace('{0}', name) : '';
});

const answer = async (allowed: boolean) => {
	if (answering.value) return;
	answering.value = true;
	try {
		await invoke('answer', { allowed });
	} finally {
		answering.value = false;
		request.value = null;
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
		<template v-if="request && text">
			<div class="flex flex-col gap-2">
				<h1 class="text-lg font-semibold text-tx-main">{{ title }}</h1>
				<p class="text-sm text-tx-muted">{{ text.explanation }}</p>
			</div>

			<p v-if="request.detail" class="text-sm text-tx-main">
				{{ request.detail }}
			</p>

			<!-- The user is deciding based on which program is asking, so being
			     honest about how sure we are is the point, not a detail. -->
			<p
				v-if="request.application.provenance === 'unverified'"
				class="rounded-corner border border-status-warning/40 bg-status-warning/10 p-2 text-xs text-status-warning"
			>
				Este programa no está instalado por el sistema, así que no podemos
				garantizar que siga siendo el mismo más adelante.
				<span class="mt-1 block break-all opacity-80">
					{{ request.application.binary_path }}
				</span>
			</p>
			<p v-else class="break-all text-xs text-tx-muted">
				{{ request.application.binary_path }}
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
