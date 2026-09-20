<!--
  Uso correcto del componente propio. Si esto deja de pasar el chequeo, o dejó
  de mirarse, o el componente cambió.
-->
<script setup lang="ts">
import ComponentePropio from './ComponentePropio.vue';
</script>

<template>
  <ComponentePropio :etiqueta="'aceptar'" :apagado="false" />
</template>
