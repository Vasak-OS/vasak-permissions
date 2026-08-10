<script lang="ts" setup>
import ActionControlsComponent from '@/components/topbar/ActionControlsComponent.vue';
</script>
<template>
  <div class="flex justify-between p-1" data-tauri-drag-region>
    <div class="flex-1 flex justify-between items-center gap-2 px-1" data-tauri-drag-region>
      <slot />
    </div>
    <ActionControlsComponent />
  </div>
</template>