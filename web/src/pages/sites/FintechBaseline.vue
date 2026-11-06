<script setup lang="ts">
import Button from 'openvue/button'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import { useToastStore } from '@/stores/toasts'
import { planBaseline } from './fintechBaseline'

type Policy = components['schemas']['Policy']

const props = defineProps<{
  siteId: string
  /** The site-level policy. */
  policy?: Policy
  /** The global defaults layer. */
  defaults?: Policy
  etag?: string
  canWrite: boolean
}>()
const emit = defineEmits<{ applied: [] }>()

const { t } = useI18n()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()

const open = ref(false)
const busy = ref(false)
const error = ref('')
const overwrite = ref(new Set<string>())

const plan = computed(() => planBaseline(props.policy, props.defaults, overwrite.value))
const changing = computed(() =>
  plan.value.rows.some((r) => r.status === 'set' || r.status === 'overwrite'),
)

const fieldKey = (path: string) => `fintech.fields.${path.replaceAll('.', '_')}`

function show(value: unknown): string {
  if (value === undefined) return t('fintech.unset')
  if (Array.isArray(value)) return value.join(', ')
  if (typeof value === 'boolean') return value ? t('common.yes') : t('common.no')
  return String(value)
}

function toggle(path: string, on: boolean) {
  const next = new Set(overwrite.value)
  if (on) next.add(path)
  else next.delete(path)
  overwrite.value = next
}

async function apply() {
  const body = plan.value.patch
  if (!body || busy.value) return
  if (!props.etag) {
    error.value = t('common.errors.preconditionRequired')
    return
  }
  error.value = ''
  busy.value = true
  try {
    await call(
      client.PATCH('/sites/{site}', {
        params: { path: { site: props.siteId }, header: ifMatch(props.etag) },
        headers: { 'Content-Type': 'application/merge-patch+json' },
        body,
      }),
      { toast: false },
    )
    toasts.success(t('fintech.applied'))
    open.value = false
    overwrite.value = new Set()
    emit('applied')
  } catch (e) {
    if (isApiError(e) && e.kind === 'stale') error.value = t('common.errors.stale')
    else error.value = isApiError(e) ? (e.detail ?? e.title) : t('common.errors.title')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section
    class="mb-6 flex max-w-3xl flex-col gap-3 rounded-sk border border-sk-border p-4"
    aria-labelledby="fintech-heading"
    data-testid="fintech-baseline"
  >
    <h2 id="fintech-heading" class="text-lg font-semibold">{{ t('fintech.title') }}</h2>
    <p class="text-sk-muted">{{ t('fintech.intro') }}</p>
    <div>
      <Button
        type="button"
        severity="secondary"
        :label="open ? t('fintech.hide') : t('fintech.review')"
        :aria-expanded="open"
        aria-controls="fintech-review"
        @click="open = !open"
      />
    </div>

    <div v-if="open" id="fintech-review" class="flex flex-col gap-3">
      <p
        v-if="plan.modeHint"
        role="status"
        class="rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
        data-testid="fintech-mode-hint"
      >
        <i class="ti ti-alert-triangle" aria-hidden="true" />
        {{ t('fintech.modeHint', { mode: plan.mode }) }}
      </p>
      <p
        v-if="plan.needsEndpoints"
        role="status"
        class="rounded-sk border border-sk-border p-3"
        data-testid="fintech-endpoints-prompt"
      >
        <i class="ti ti-info-circle" aria-hidden="true" />
        {{ t('fintech.endpointsPrompt') }}
      </p>

      <div class="overflow-x-auto">
        <table class="w-full text-left" data-testid="fintech-diff">
          <caption class="sr-only">
            {{
              t('fintech.table.caption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border">
              <th scope="col" class="py-2 pr-4">{{ t('fintech.table.setting') }}</th>
              <th scope="col" class="py-2 pr-4">{{ t('fintech.table.current') }}</th>
              <th scope="col" class="py-2 pr-4">{{ t('fintech.table.baseline') }}</th>
              <th scope="col" class="py-2">{{ t('fintech.table.result') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in plan.rows" :key="row.path" class="border-b border-sk-border">
              <th scope="row" class="py-2 pr-4 font-normal">
                {{ t(fieldKey(row.path)) }}
              </th>
              <td class="py-2 pr-4 font-mono">{{ show(row.current) }}</td>
              <td class="py-2 pr-4 font-mono">{{ show(row.baseline) }}</td>
              <td class="py-2">
                <span :data-status="row.status">{{ t(`fintech.status.${row.status}`) }}</span>
                <label
                  v-if="canWrite && (row.status === 'kept' || row.status === 'overwrite')"
                  class="mt-1 flex items-center gap-2 text-sm"
                >
                  <input
                    type="checkbox"
                    class="size-4 accent-[var(--sk-accent)]"
                    :checked="row.status === 'overwrite'"
                    @change="toggle(row.path, ($event.target as HTMLInputElement).checked)"
                  />
                  {{ t('fintech.replace', { setting: t(fieldKey(row.path)) }) }}
                </label>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="!changing" role="status" class="text-sk-muted">{{ t('fintech.nothing') }}</p>
      <p v-if="!canWrite" role="status" class="text-sk-muted">{{ t('fintech.noWrite') }}</p>
      <p v-if="error" role="alert" class="text-sk-danger">{{ error }}</p>
      <div v-if="canWrite">
        <Button
          type="button"
          :label="busy ? t('fintech.applying') : t('fintech.apply')"
          :disabled="busy || !changing"
          @click="apply"
        />
      </div>
    </div>
  </section>
</template>
