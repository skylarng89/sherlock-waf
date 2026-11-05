<script setup lang="ts">
import Button from 'openvue/button'
import { computed, ref, useId } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import { formatTime } from '@/pages/history/format'
import { PARANOIA_LEVELS, type ParanoiaImpact } from './lib'

const props = defineProps<{
  site: string
  detect: number
  block: number
  canWrite: boolean
  busy: boolean
  /** Persists WAF policy fields; resolves true on success. */
  save: (waf: Record<string, number>) => Promise<boolean>
}>()

const { t } = useI18n()
const { client, call } = useApi()
const uid = useId()
const selectId = `pl-${uid}`

const target = ref<number>(Math.min(props.block + 1, 4))
const impact = ref<ParanoiaImpact>()
const state = ref<'idle' | 'loading' | 'ready' | 'error'>('idle')
const confirm = ref(false)

const sameLevel = computed(() => target.value === props.block)
const canApply = computed(
  () => props.canWrite && impact.value?.observable === true && !sameLevel.value && !props.busy,
)

async function check() {
  state.value = 'loading'
  impact.value = undefined
  try {
    const res = await call(
      client.GET('/sites/{site}/paranoia-impact', {
        params: { path: { site: props.site }, query: { target: target.value } },
      }),
      { toast: false },
    )
    impact.value = res.data
    state.value = 'ready'
  } catch (e) {
    if (!isApiError(e)) throw e
    state.value = 'error'
  }
}

async function apply() {
  confirm.value = false
  // Detection must be at least the blocking level or the CRS never evaluates the new rules.
  const waf: Record<string, number> = { blocking_paranoia_level: target.value }
  if (props.detect < target.value) waf.paranoia_level = target.value
  if (await props.save(waf)) await check()
}

async function raiseDetection() {
  if (await props.save({ paranoia_level: target.value })) await check()
}
</script>

<template>
  <section aria-labelledby="tn-paranoia" class="rounded-sk-lg border border-sk-border p-4">
    <h2 id="tn-paranoia" class="mb-1 text-lg font-semibold">{{ t('tuning.paranoia.title') }}</h2>
    <p class="mb-2" data-testid="pl-current">
      {{ t('tuning.paranoia.current', { detect, block }) }}
    </p>
    <details class="mb-3">
      <summary class="cursor-pointer">{{ t('tuning.paranoia.explainer') }}</summary>
      <ul class="mt-2 list-disc pl-6 text-sm" data-testid="pl-levels">
        <li v-for="n in PARANOIA_LEVELS" :key="n">{{ t(`tuning.paranoia.levels.${n}`) }}</li>
      </ul>
    </details>

    <div class="flex flex-wrap items-end gap-3">
      <div class="flex flex-col gap-1">
        <label :for="selectId" class="font-medium">{{ t('tuning.paranoia.target') }}</label>
        <select
          :id="selectId"
          v-model.number="target"
          class="rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2"
        >
          <option v-for="n in PARANOIA_LEVELS" :key="n" :value="n">
            {{ t('tuning.paranoia.targetOption', { n }) }}
          </option>
        </select>
      </div>
      <Button :label="t('tuning.paranoia.check')" severity="secondary" @click="check" />
    </div>

    <div class="mt-3" role="status" aria-live="polite">
      <p v-if="state === 'loading'">{{ t('tuning.paranoia.loading') }}…</p>
    </div>
    <p v-if="state === 'error'" role="alert" class="text-sk-danger">
      {{ t('tuning.paranoia.loadFailed') }}
    </p>

    <div
      v-if="impact && state === 'ready'"
      class="mt-3 flex flex-col gap-3"
      data-testid="pl-impact"
    >
      <template v-if="!impact.observable">
        <div
          class="rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
          data-testid="pl-not-observable"
        >
          <h3 class="font-semibold">
            <i class="ti ti-eye-off" aria-hidden="true" /> {{ t('tuning.paranoia.notObservable') }}
          </h3>
          <p v-if="impact.advice" class="mt-1">
            <strong>{{ t('tuning.paranoia.advice') }}:</strong> {{ impact.advice }}
          </p>
          <p class="mt-1">{{ t('tuning.paranoia.raiseDetectionHelp') }}</p>
        </div>
        <div v-if="canWrite">
          <Button
            :label="t('tuning.paranoia.raiseDetection', { n: impact.target_paranoia_level })"
            :disabled="busy"
            data-testid="pl-raise-detection"
            @click="raiseDetection"
          />
        </div>
      </template>
      <template v-else>
        <p class="text-sk-muted">
          {{
            t('tuning.paranoia.window', {
              scanned: impact.events_scanned,
              from: formatTime(impact.from),
              to: formatTime(impact.to),
            })
          }}
        </p>
        <p>{{ t('tuning.paranoia.already', { n: impact.already_blocking }) }}</p>
        <p class="text-lg font-semibold" data-testid="pl-additional">
          {{ t('tuning.paranoia.additional', { n: impact.additional_blocks }) }}
        </p>
        <p v-if="impact.additional_blocks === 0" class="text-sk-success">
          <i class="ti ti-circle-check" aria-hidden="true" />
          {{ t('tuning.paranoia.noneAdditional') }}
        </p>
        <p v-if="impact.truncated" class="text-sm text-sk-muted">
          {{ t('tuning.paranoia.truncated') }}
        </p>
        <div v-if="impact.by_rule.length" class="grid gap-4 md:grid-cols-2">
          <table class="w-full text-left text-sm" data-testid="pl-by-rule">
            <caption class="mb-1 text-left font-medium">
              {{
                t('tuning.paranoia.byRule')
              }}
            </caption>
            <thead>
              <tr class="border-b border-sk-border-strong">
                <th scope="col" class="p-1">{{ t('tuning.paranoia.colRule') }}</th>
                <th scope="col" class="p-1">{{ t('tuning.paranoia.colCount') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in impact.by_rule" :key="r.rule_id" class="border-b border-sk-border">
                <th scope="row" class="p-1 font-mono font-normal">{{ r.rule_id }}</th>
                <td class="p-1 font-mono">{{ r.count }}</td>
              </tr>
            </tbody>
          </table>
          <table class="w-full text-left text-sm" data-testid="pl-by-path">
            <caption class="mb-1 text-left font-medium">
              {{
                t('tuning.paranoia.byPath')
              }}
            </caption>
            <thead>
              <tr class="border-b border-sk-border-strong">
                <th scope="col" class="p-1">{{ t('tuning.paranoia.colPath') }}</th>
                <th scope="col" class="p-1">{{ t('tuning.paranoia.colCount') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in impact.by_path" :key="r.path" class="border-b border-sk-border">
                <th scope="row" class="break-all p-1 font-mono font-normal">{{ r.path }}</th>
                <td class="p-1 font-mono">{{ r.count }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <ul v-if="impact.sample_event_ids.length" class="text-sm">
          <li class="font-medium">{{ t('tuning.paranoia.sampleEvents') }}</li>
          <li v-for="id in impact.sample_event_ids.slice(0, 5)" :key="id">
            <RouterLink
              :to="{ name: 'event-detail', params: { id } }"
              class="font-mono text-sk-accent underline"
            >
              {{ id }}
            </RouterLink>
          </li>
        </ul>
        <div v-if="canWrite" class="flex flex-wrap items-center gap-2">
          <Button
            :label="t('tuning.paranoia.apply', { n: target })"
            :disabled="!canApply"
            data-testid="pl-apply"
            @click="confirm = true"
          />
          <span v-if="sameLevel" class="text-sm text-sk-muted">{{
            t('tuning.paranoia.sameLevel')
          }}</span>
        </div>
      </template>
    </div>

    <SkConfirmDialog
      v-if="canWrite"
      v-model:open="confirm"
      :title="t('tuning.paranoia.applyConfirmTitle', { n: target })"
      :message="t('tuning.paranoia.applyConfirmMessage')"
      :confirm-label="t('tuning.paranoia.apply', { n: target })"
      @confirm="apply"
    />
  </section>
</template>
