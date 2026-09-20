<!--
  Un componente como los de la aplicación: propiedades declaradas con
  `defineProps` y nada más. Está acá para que el test pueda comprobar que
  `vue-tsc` **también** sigue mirando lo propio, y no sólo lo que viene de la
  librería. Las dos cosas se rompen por caminos distintos.
-->
<script setup lang="ts">
defineProps<{ etiqueta: string; apagado?: boolean }>();
</script>

<template>
  <button type="button" :disabled="apagado">{{ etiqueta }}</button>
</template>
