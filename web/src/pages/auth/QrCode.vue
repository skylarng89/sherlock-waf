<script setup lang="ts">
import { computed } from 'vue'
import { qrMatrix } from '@/lib/qr'

const props = defineProps<{ value: string; label: string }>()

const QUIET_ZONE = 4

const geometry = computed(() => {
  const matrix = qrMatrix(props.value)
  const size = matrix.length + QUIET_ZONE * 2
  let d = ''
  matrix.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) d += `M${x + QUIET_ZONE} ${y + QUIET_ZONE}h1v1h-1z`
    }),
  )
  return { size, d }
})
</script>

<template>
  <!-- Fixed black on white regardless of theme: scanners need the contrast. Built from
       the module matrix as SVG elements; never injected as HTML. -->
  <svg
    role="img"
    :aria-label="label"
    :viewBox="`0 0 ${geometry.size} ${geometry.size}`"
    class="size-48 rounded-sk"
    shape-rendering="crispEdges"
  >
    <rect width="100%" height="100%" fill="#ffffff" />
    <path :d="geometry.d" fill="#000000" />
  </svg>
</template>
