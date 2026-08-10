<script lang="ts" setup>
import TopBarComponent from '@/components/topbar/TopBarComponent.vue';
</script>
<template>
  <div
    class="h-screen w-screen bg-ui-bg/80 rounded-corner-window flex flex-col border border-ui-border overflow-hidden">
    <TopBarComponent>
    </TopBarComponent>
    <div class="flex-1 flex p-1">
      <p>VAPP</p>
    </div>
  </div>
</template>
