<script setup lang="ts">
import Button from 'openvue/button'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { components } from '@/api/schema'
import { ApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'

type Result = components['schemas']['TestUpstreamResult']

const props = defineProps<{ target: string; tls: boolean; skipVerify: boolean }>()
const { t, te } = useI18n()
const { client, call } = useApi()

const busy = ref(false)
const result = ref<Result>()
const failure = ref<string>()

// A result describes one target; once the inputs change it is stale.
watch(
  () => [props.target, props.tls, props.skipVerify],
  () => {
    result.value = undefined
    failure.value = undefined
  },
)

const errorText = computed(() => {
  const cls = result.value?.error
  if (!cls) return ''
  return te(`setup.test.error.${cls}`) ? t(`setup.test.error.${cls}`) : t('setup.test.error.other')
})

async function run() {
  if (!props.target.trim()) {
    failure.value = t('setup.test.needTarget')
    return
  }
  busy.value = true
  result.value = undefined
  failure.value = undefined
  try {
    const res = await call(
      client.POST('/system/test-upstream', {
        body: { target: props.target.trim(), tls: props.tls, tls_skip_verify: props.skipVerify },
      }),
      { toast: false },
    )
    result.value = res.data
  } catch (e) {
    failure.value = e instanceof ApiError ? (e.detail ?? e.title) : t('common.errors.unknown')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="flex flex-col gap-2">
    <div>
      <Button
        type="button"
        severity="secondary"
        icon="ti ti-plug-connected"
        :label="t('setup.test.run')"
        :loading="busy"
        :disabled="busy"
        @click="run"
      />
    </div>
    <p v-if="result?.reachable" role="status" class="text-sk-success" data-testid="test-ok">
      <i class="ti ti-circle-check" aria-hidden="true" />
      {{
        result.status
          ? t('setup.test.reachableStatus', { status: result.status, ms: result.latency_ms })
          : t('setup.test.reachable', { ms: result.latency_ms })
      }}
    </p>
    <p v-else-if="result" role="alert" class="text-sk-danger" data-testid="test-fail">
      <i class="ti ti-circle-x" aria-hidden="true" />
      {{ errorText }}
    </p>
    <p v-if="failure" role="alert" class="text-sk-danger">
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ failure }}
    </p>
  </div>
</template>
