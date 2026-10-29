<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import { challengeCounts } from './policy'

const REFRESH_MS = 30_000
const DAY_MS = 24 * 3_600_000

const { t } = useI18n()
const { client, call } = useApi()

const counts = ref<ReturnType<typeof challengeCounts>>()
const sampled = ref(false)
const failed = ref(false)
let timer: ReturnType<typeof setInterval> | undefined

async function load() {
  const to = new Date(Math.floor(Date.now() / 60_000) * 60_000)
  const from = new Date(to.getTime() - DAY_MS)
  try {
    // The bot module records its outcome as a finding, so the rule dimension carries it.
    const res = await call(
      client.GET('/stats/top', {
        params: {
          query: { dim: 'rule', from: from.toISOString(), to: to.toISOString(), limit: 100 },
        },
      }),
      { toast: false },
    )
    counts.value = challengeCounts(res.data.items)
    sampled.value = res.data.sampled
    failed.value = false
  } catch (e) {
    if (!isApiError(e)) throw e
    failed.value = true
  }
}

onMounted(() => {
  void load()
  timer = setInterval(() => void load(), REFRESH_MS)
})
onBeforeUnmount(() => timer && clearInterval(timer))
</script>

<template>
  <section
    aria-labelledby="card-bot"
    class="rounded-sk-lg border border-sk-border bg-sk-surface p-4"
    data-testid="bot-stats"
  >
    <h2 id="card-bot" class="text-sm font-medium text-sk-muted">{{ t('bot.stats.title') }}</h2>
    <p v-if="failed" role="alert" class="text-sk-danger">{{ t('bot.stats.loadError') }}</p>
    <template v-else-if="counts">
      <dl class="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 text-sm">
        <dt class="text-sk-muted">{{ t('bot.stats.passed') }}</dt>
        <dd data-testid="challenge-passed">
          <i class="ti ti-circle-check" aria-hidden="true" /> {{ counts.passed }}
        </dd>
        <dt class="text-sk-muted">{{ t('bot.stats.failed') }}</dt>
        <dd data-testid="challenge-failed">
          <i class="ti ti-circle-x" aria-hidden="true" /> {{ counts.failed }}
        </dd>
      </dl>
      <p class="mt-2 text-xs text-sk-muted">
        {{ t('bot.stats.description') }}
        <template v-if="sampled">{{ t('bot.stats.sampled') }}</template>
      </p>
    </template>
  </section>
</template>
