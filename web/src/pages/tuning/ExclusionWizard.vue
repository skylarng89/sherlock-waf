<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError, type ApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import { useToastStore } from '@/stores/toasts'
import {
  removalParts,
  scopeMethods,
  scopePaths,
  sortedWarnings,
  type ExclusionProposal,
} from './lib'

export interface WizardFinding {
  ruleId: string
  message: string
}

const props = defineProps<{
  open: boolean
  site: string
  eventId: string
  findings: WizardFinding[]
}>()
const emit = defineEmits<{ 'update:open': [value: boolean]; created: [id: string] }>()

const DAYS = 30
const { t } = useI18n()
const { client, call, ifMatch } = useApi()
const toasts = useToastStore()
const uid = useId()
const titleId = `xw-${uid}-title`

const dialog = ref<HTMLDialogElement>()
const closeButton = ref<HTMLButtonElement>()
let opener: HTMLElement | null = null

const ruleId = ref<string>()
const scope = ref<'target' | 'rule'>('target')
const proposal = ref<ExclusionProposal>()
const etag = ref<string>()
const state = ref<'idle' | 'loading' | 'ready' | 'error'>('idle')
const error = ref<ApiError>()
const stale = ref(false)
const acknowledged = ref(false)
const busy = ref(false)
const createdId = ref<string>()
let seq = 0

const uniqueFindings = computed(() => {
  const seen = new Set<string>()
  return props.findings.filter((f) => f.ruleId && !seen.has(f.ruleId) && seen.add(f.ruleId))
})
const warnings = computed(() => (proposal.value ? sortedWarnings(proposal.value) : []))
const needsAck = computed(() => proposal.value?.requires_acknowledgement === true)
const canCreate = computed(
  () =>
    state.value === 'ready' &&
    !busy.value &&
    !stale.value &&
    (!needsAck.value || acknowledged.value),
)

async function prepare() {
  const mine = ++seq
  state.value = 'loading'
  error.value = undefined
  stale.value = false
  acknowledged.value = false
  proposal.value = undefined
  try {
    const [p, list] = await Promise.all([
      call(
        client.POST('/sites/{site}/exclusions/propose', {
          params: { path: { site: props.site } },
          body: {
            event_id: props.eventId,
            scope: scope.value,
            days: DAYS,
            ...(ruleId.value ? { rule_id: ruleId.value } : {}),
          },
        }),
        { toast: false },
      ),
      call(client.GET('/sites/{site}/exclusions', { params: { path: { site: props.site } } }), {
        toast: false,
      }),
    ])
    if (mine !== seq) return
    proposal.value = p.data
    etag.value = list.etag
    state.value = 'ready'
  } catch (e) {
    if (!isApiError(e)) throw e
    if (mine !== seq) return
    error.value = e
    state.value = 'error'
  }
}

async function sync(open: boolean) {
  const el = dialog.value
  if (!el) return
  if (open && !el.open) {
    opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    createdId.value = undefined
    scope.value = 'target'
    ruleId.value = undefined
    el.showModal()
    void prepare()
    await nextTick()
    closeButton.value?.focus()
  } else if (!open && el.open) {
    el.close()
    opener?.focus()
    opener = null
  }
}
watch(() => props.open, sync, { flush: 'post' })
onMounted(() => sync(props.open))
onBeforeUnmount(() => {
  if (dialog.value?.open) dialog.value.close()
})

function close() {
  emit('update:open', false)
}

function onNativeCancel(e: Event) {
  e.preventDefault()
  if (!busy.value) close()
}

function pickRule(e: Event) {
  ruleId.value = (e.target as HTMLSelectElement).value || undefined
  void prepare()
}
function pickScope(value: 'target' | 'rule') {
  scope.value = value
  void prepare()
}

async function create() {
  const p = proposal.value
  if (!p || !canCreate.value) return
  if (!etag.value) {
    error.value = undefined
    stale.value = true
    return
  }
  busy.value = true
  try {
    await call(
      client.POST('/sites/{site}/exclusions', {
        params: { path: { site: props.site }, header: ifMatch(etag.value) },
        body: {
          exclusion: p.exclusion,
          event_id: props.eventId,
          acknowledge_warnings: needsAck.value ? acknowledged.value : undefined,
        },
      }),
      { toast: false },
    )
    createdId.value = p.exclusion.id
    toasts.success(t('tuning.wizard.created', { id: p.exclusion.id }))
    emit('created', p.exclusion.id)
  } catch (e) {
    if (!isApiError(e)) throw e
    if (e.kind === 'stale' || e.kind === 'precondition_required') stale.value = true
    else toasts.error(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <dialog
    ref="dialog"
    :aria-labelledby="titleId"
    class="m-auto max-h-[90vh] w-[min(40rem,calc(100vw-2rem))] overflow-y-auto rounded-sk-lg border border-sk-border-strong bg-sk-surface p-6 text-sk-text backdrop:bg-black/50"
    data-testid="exclusion-wizard"
    @cancel="onNativeCancel"
  >
    <form class="flex flex-col gap-4" @submit.prevent="create">
      <h2 :id="titleId" class="text-lg font-semibold">{{ t('tuning.wizard.title') }}</h2>

      <template v-if="createdId">
        <p role="status" class="text-sk-success" data-testid="wizard-created">
          <i class="ti ti-circle-check" aria-hidden="true" />
          {{ t('tuning.wizard.created', { id: createdId }) }}
        </p>
        <div class="flex justify-end gap-2">
          <RouterLink
            :to="{ name: 'site-tuning', params: { site } }"
            class="rounded-sk border border-sk-border-strong px-4 py-2 hover:bg-sk-surface-muted"
          >
            {{ t('tuning.wizard.viewTuning') }}
          </RouterLink>
          <button
            ref="closeButton"
            type="button"
            class="rounded-sk bg-sk-accent px-4 py-2 font-medium text-sk-accent-contrast"
            @click="close"
          >
            {{ t('common.actions.close') }}
          </button>
        </div>
      </template>

      <template v-else>
        <p class="text-sk-muted">{{ t('tuning.wizard.intro') }}</p>

        <div v-if="uniqueFindings.length > 1" class="flex flex-col gap-1">
          <label :for="`${titleId}-rule`" class="font-medium">{{
            t('tuning.wizard.finding')
          }}</label>
          <select
            :id="`${titleId}-rule`"
            class="rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2"
            @change="pickRule"
          >
            <option value="">{{ uniqueFindings[0]?.ruleId }}</option>
            <option v-for="f in uniqueFindings.slice(1)" :key="f.ruleId" :value="f.ruleId">
              {{ t('tuning.wizard.findingOption', { rule: f.ruleId, message: f.message }) }}
            </option>
          </select>
        </div>

        <fieldset class="flex flex-col gap-1">
          <legend class="font-medium">{{ t('tuning.wizard.scope') }}</legend>
          <label class="flex items-center gap-2">
            <input
              type="radio"
              name="xw-scope"
              :checked="scope === 'target'"
              @change="pickScope('target')"
            />
            {{ t('tuning.wizard.scopeTargetNoTarget') }}
          </label>
          <label class="flex items-center gap-2">
            <input
              type="radio"
              name="xw-scope"
              :checked="scope === 'rule'"
              @change="pickScope('rule')"
            />
            {{ t('tuning.wizard.scopeRule') }}
          </label>
        </fieldset>

        <p v-if="state === 'loading'" role="status">{{ t('tuning.wizard.loading') }}…</p>
        <p v-else-if="state === 'error'" role="alert" class="text-sk-danger">
          {{ t('tuning.wizard.loadFailed') }} {{ error?.title }}
        </p>

        <template v-else-if="state === 'ready' && proposal">
          <section aria-labelledby="xw-proposal" data-testid="wizard-proposal">
            <h3 id="xw-proposal" class="mb-1 font-semibold">{{ t('tuning.wizard.proposal') }}</h3>
            <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
              <dt class="text-sk-muted">{{ t('tuning.wizard.description') }}</dt>
              <dd>{{ proposal.exclusion.description || proposal.exclusion.id }}</dd>
              <dt class="text-sk-muted">{{ t('tuning.wizard.paths') }}</dt>
              <dd class="break-all font-mono">
                {{ scopePaths(proposal.exclusion).join(', ') || t('tuning.exclusions.allPaths') }}
              </dd>
              <dt class="text-sk-muted">{{ t('tuning.wizard.methods') }}</dt>
              <dd class="font-mono">
                {{
                  scopeMethods(proposal.exclusion).join(', ') || t('tuning.exclusions.allMethods')
                }}
              </dd>
              <dt class="text-sk-muted">{{ t('tuning.wizard.removes') }}</dt>
              <dd class="break-all font-mono">
                <span v-for="(p, n) in removalParts(proposal.exclusion)" :key="n" class="block">
                  {{ t(`tuning.exclusions.${p.key}`, p.params) }}
                </span>
              </dd>
            </dl>
          </section>

          <section aria-labelledby="xw-impact" data-testid="wizard-impact">
            <h3 id="xw-impact" class="mb-1 font-semibold">
              {{ t('tuning.wizard.impact', { days: DAYS }) }}
            </h3>
            <dl class="grid grid-cols-[1fr_max-content] gap-x-4 gap-y-1 text-sm">
              <dt>{{ t('tuning.wizard.scanned') }}</dt>
              <dd class="font-mono" data-testid="impact-scanned">
                {{ proposal.impact.events_scanned }}
              </dd>
              <dt>{{ t('tuning.wizard.matching') }}</dt>
              <dd class="font-mono" data-testid="impact-matching">
                {{ proposal.impact.matching_events }}
              </dd>
              <dt>{{ t('tuning.wizard.noTrigger') }}</dt>
              <dd class="font-mono" data-testid="impact-no-trigger">
                {{ proposal.impact.no_longer_triggering }}
              </dd>
              <dt>{{ t('tuning.wizard.noBlock') }}</dt>
              <dd class="font-mono" data-testid="impact-no-block">
                {{ proposal.impact.no_longer_blocking }}
              </dd>
            </dl>
            <p v-if="proposal.impact.truncated" class="mt-1 text-sm text-sk-muted">
              {{ t('tuning.wizard.truncated') }}
            </p>
            <template v-if="Object.keys(proposal.impact.by_rule).length">
              <h4 class="mt-2 text-sm font-medium">{{ t('tuning.wizard.byRule') }}</h4>
              <ul class="text-sm">
                <li v-for="(n, rule) in proposal.impact.by_rule" :key="rule" class="font-mono">
                  {{ rule }}: {{ n }}
                </li>
              </ul>
            </template>
          </section>

          <section v-if="warnings.length" aria-labelledby="xw-warn" data-testid="wizard-warnings">
            <h3 id="xw-warn" class="mb-1 font-semibold">{{ t('tuning.wizard.warnings') }}</h3>
            <ul class="flex flex-col gap-1">
              <li
                v-for="(w, n) in warnings"
                :key="n"
                :class="[
                  'rounded-sk border p-2',
                  w.severity === 'critical'
                    ? 'border-sk-danger bg-sk-danger-bg text-sk-danger'
                    : w.severity === 'warning'
                      ? 'border-sk-warning bg-sk-warning-bg text-sk-warning'
                      : 'border-sk-info bg-sk-info-bg text-sk-info',
                ]"
              >
                <i
                  :class="w.severity === 'info' ? 'ti ti-info-circle' : 'ti ti-alert-triangle'"
                  aria-hidden="true"
                />
                <strong>{{ t(`tuning.wizard.sev.${w.severity}`) }}:</strong> {{ w.message }}
              </li>
            </ul>
          </section>

          <label v-if="needsAck" class="flex items-start gap-2 font-medium">
            <input v-model="acknowledged" type="checkbox" class="mt-1 size-4" />
            {{ t('tuning.wizard.acknowledge') }}
          </label>
        </template>

        <div
          v-if="stale"
          role="alert"
          class="flex flex-wrap items-center gap-2 rounded-sk border border-sk-warning bg-sk-warning-bg p-2 text-sk-warning"
        >
          {{ t('tuning.wizard.stale') }}
          <button type="button" class="underline" @click="prepare">
            {{ t('tuning.wizard.reload') }}
          </button>
        </div>

        <div class="flex justify-end gap-2">
          <button
            ref="closeButton"
            type="button"
            :disabled="busy"
            class="rounded-sk border border-sk-border-strong px-4 py-2 hover:bg-sk-surface-muted disabled:opacity-60"
            @click="close"
          >
            {{ t('common.actions.cancel') }}
          </button>
          <button
            type="submit"
            :disabled="!canCreate"
            :aria-describedby="needsAck && !acknowledged ? `${titleId}-ack` : undefined"
            class="rounded-sk bg-sk-accent px-4 py-2 font-medium text-sk-accent-contrast hover:bg-sk-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
          >
            {{ t('tuning.wizard.create') }}
          </button>
        </div>
        <p v-if="needsAck && !acknowledged" :id="`${titleId}-ack`" class="text-sm text-sk-muted">
          {{ t('tuning.wizard.acknowledgeRequired') }}
        </p>
      </template>
    </form>
  </dialog>
</template>
