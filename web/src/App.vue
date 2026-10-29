<script setup lang="ts">
import { computed } from 'vue'
import { RouterView, useRoute } from 'vue-router'
import SkToaster from '@/components/SkToaster.vue'
import AppShell from '@/layouts/AppShell.vue'
import AuthLayout from '@/layouts/AuthLayout.vue'

const route = useRoute()
const layout = computed(() => (route.meta.layout === 'auth' ? AuthLayout : AppShell))
</script>

<template>
  <component :is="layout" v-if="route.matched.length">
    <RouterView />
  </component>
  <SkToaster />
</template>
