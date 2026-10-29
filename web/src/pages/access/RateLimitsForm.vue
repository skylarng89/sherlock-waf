<script setup lang="ts">
import Button from 'openvue/button'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { setAt, type JsonObject } from '@/pages/sites/lib/json'
import type { Policy, PolicyLayer } from '@/pages/sites/lib/layers'
import {
  inheritedRateLimits,
  matchSummary,
  OPT_OUT_PREFIX,
  optOutNames,
  rateLimitSummary,
  type RateLimit,
} from './policy'
import RateLimitEditor from './RateLimitEditor.vue'

const props = defineProps<{
  /** Parent levels, closest first. Without them there is nothing to inherit or opt out of. */
  layers?: PolicyLayer[]
  disabled?: boolean
  errorFor: (path: string) => string | undefined
}>()
const model = defineModel<Policy>({ required: true })
const { t } = useI18n()

const ROW_FIELDS = [
  'name',
  'limit',
  'window',
  'key',
  'action',
  'match',
  'match.paths',
  'match.methods',
]

const own = computed(() => model.value.rate_limits ?? [])
const inherited = computed(() => inheritedRateLimits(props.layers ?? []))
const optedOut = computed(() => new Set(optOutNames(model.value.opt_out)))
const replaced = (name: string) => own.value.some((i) => i.name === name)
const inheritedByName = (name: string) => inherited.value.find((i) => i.item.name === name)

/** Inherited items this level still receives (not replaced here). */
const passive = computed(() => inherited.value.filter((i) => !replaced(i.item.name)))

// -1: a new item. undefined: no editor open.
const editing = ref<number>()
const editedItem = computed(() =>
  editing.value === undefined ? undefined : own.value[editing.value],
)
const taken = computed(() => own.value.filter((_, i) => i !== editing.value).map((i) => i.name))

function withItems(policy: Policy, items: RateLimit[]): Policy {
  return setAt(policy as JsonObject, 'rate_limits', items.length ? items : undefined) as Policy
}

function withOptOut(policy: Policy, names: Set<string>): Policy {
  const others = (policy.opt_out ?? []).filter((o) => !o.startsWith(OPT_OUT_PREFIX))
  const all = [...others, ...[...names].map((n) => `${OPT_OUT_PREFIX}${n}`)]
  return setAt(policy as JsonObject, 'opt_out', all.length ? all : undefined) as Policy
}

function toggleOptOut(name: string, on: boolean) {
  const next = new Set(optedOut.value)
  if (on) next.add(name)
  else next.delete(name)
  model.value = withOptOut(model.value, next)
}

function apply(item: RateLimit) {
  const items = [...own.value]
  if (editing.value === undefined || editing.value < 0) items.push(item)
  else items[editing.value] = item
  // The server refuses an item that is both defined and opted out at one level, and the
  // model only updates after the parent re-renders: write both changes in one assignment.
  const keep = new Set(optedOut.value)
  keep.delete(item.name)
  model.value = withOptOut(withItems(model.value, items), keep)
  editing.value = undefined
}

function remove(index: number) {
  model.value = withItems(
    model.value,
    own.value.filter((_, i) => i !== index),
  )
  if (editing.value === index) editing.value = undefined
}

function rowErrors(index: number): string[] {
  return ROW_FIELDS.map((f) => props.errorFor(`rate_limits.${index}.${f}`)).filter(
    (m): m is string => Boolean(m),
  )
}

const listErrors = computed(() =>
  [props.errorFor('rate_limits'), props.errorFor('opt_out')].filter((m): m is string => Boolean(m)),
)
</script>

<template>
  <div class="flex flex-col gap-4" data-testid="rate-limits-form">
    <p class="text-sm text-sk-muted">{{ t('access.rateLimits.help') }}</p>
    <ul v-if="listErrors.length" role="alert" class="text-sk-danger">
      <li v-for="e in listErrors" :key="e">
        <i class="ti ti-alert-circle" aria-hidden="true" />
        {{ e }}
      </li>
    </ul>

    <div
      class="overflow-x-auto"
      tabindex="0"
      role="region"
      :aria-label="t('access.rateLimits.scroll')"
    >
      <table class="w-full text-left">
        <caption class="sr-only">
          {{
            t('access.rateLimits.caption')
          }}
        </caption>
        <thead>
          <tr class="border-b border-sk-border-strong">
            <th scope="col" class="p-2">{{ t('access.rateLimits.cols.name') }}</th>
            <th scope="col" class="p-2">{{ t('access.rateLimits.cols.match') }}</th>
            <th scope="col" class="p-2">{{ t('access.rateLimits.cols.limit') }}</th>
            <th scope="col" class="p-2">{{ t('access.rateLimits.cols.action') }}</th>
            <th scope="col" class="p-2">{{ t('access.rateLimits.cols.origin') }}</th>
            <th scope="col" class="p-2">{{ t('access.rateLimits.cols.controls') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="own.length === 0 && passive.length === 0">
            <td colspan="6" class="p-3 text-sk-muted">{{ t('access.rateLimits.empty') }}</td>
          </tr>
          <template v-for="(rl, i) in own" :key="`own-${rl.name}-${i}`">
            <tr class="border-b border-sk-border" :data-testid="`own-${rl.name}`">
              <th scope="row" class="p-2 font-mono text-sm font-normal">{{ rl.name }}</th>
              <td class="p-2 font-mono text-sm">{{ matchSummary(rl) }}</td>
              <td class="p-2">{{ rateLimitSummary(rl) }}</td>
              <td class="p-2">{{ t(`access.actions.${rl.action ?? 'block'}`) }}</td>
              <td class="p-2">
                <span v-if="inheritedByName(rl.name)" class="inline-flex items-center gap-1">
                  <i class="ti ti-replace" aria-hidden="true" />
                  {{
                    t('access.rateLimits.overridesItem', {
                      source: inheritedByName(rl.name)?.label,
                    })
                  }}
                </span>
                <span v-else class="inline-flex items-center gap-1">
                  <i class="ti ti-pencil" aria-hidden="true" />
                  {{ t('access.rateLimits.definedHere') }}
                </span>
              </td>
              <td class="p-2">
                <div v-if="!disabled" class="flex gap-2">
                  <button
                    type="button"
                    class="rounded-sk border border-sk-border-strong px-2 py-1"
                    :aria-label="t('access.rateLimits.editItem', { name: rl.name })"
                    @click="editing = i"
                  >
                    <i class="ti ti-pencil" aria-hidden="true" />
                    {{ t('common.actions.edit') }}
                  </button>
                  <button
                    type="button"
                    class="rounded-sk border border-sk-danger px-2 py-1 text-sk-danger"
                    :aria-label="t('access.rateLimits.removeItem', { name: rl.name })"
                    @click="remove(i)"
                  >
                    <i class="ti ti-trash" aria-hidden="true" />
                    {{ t('access.rateLimits.remove') }}
                  </button>
                </div>
              </td>
            </tr>
            <tr v-if="rowErrors(i).length" class="border-b border-sk-border">
              <td colspan="6" class="p-2">
                <ul role="alert" class="text-sk-danger">
                  <li v-for="e in rowErrors(i)" :key="e">
                    <i class="ti ti-alert-circle" aria-hidden="true" />
                    {{ t('access.rateLimits.rowError', { name: rl.name, message: e }) }}
                  </li>
                </ul>
              </td>
            </tr>
          </template>
          <tr
            v-for="inh in passive"
            :key="`inh-${inh.item.name}`"
            :class="[
              'border-b border-sk-border',
              optedOut.has(inh.item.name) ? 'text-sk-muted' : '',
            ]"
            :data-testid="`inherited-${inh.item.name}`"
          >
            <th scope="row" class="p-2 font-mono text-sm font-normal">{{ inh.item.name }}</th>
            <td class="p-2 font-mono text-sm">{{ matchSummary(inh.item) }}</td>
            <td class="p-2">{{ rateLimitSummary(inh.item) }}</td>
            <td class="p-2">{{ t(`access.actions.${inh.item.action ?? 'block'}`) }}</td>
            <td class="p-2">
              <span class="inline-flex items-center gap-1">
                <i class="ti ti-corner-left-down" aria-hidden="true" />
                {{ t('access.rateLimits.inheritedFrom', { source: inh.label }) }}
              </span>
              <span
                v-if="optedOut.has(inh.item.name)"
                class="ml-2 inline-flex items-center gap-1 font-medium"
              >
                <i class="ti ti-ban" aria-hidden="true" />
                {{ t('access.rateLimits.optedOut') }}
              </span>
            </td>
            <td class="p-2">
              <label class="flex items-center gap-2">
                <input
                  type="checkbox"
                  class="size-4 accent-[var(--sk-accent)]"
                  :checked="optedOut.has(inh.item.name)"
                  :disabled="disabled"
                  @change="toggleOptOut(inh.item.name, ($event.target as HTMLInputElement).checked)"
                />
                {{ t('access.rateLimits.optOut', { name: inh.item.name }) }}
              </label>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <p v-if="passive.length" class="text-sm text-sk-muted">
      <i class="ti ti-history" aria-hidden="true" />
      {{ t('access.rateLimits.optOutAudit') }}
    </p>

    <RateLimitEditor
      v-if="editing !== undefined"
      :key="editing"
      :item="editedItem"
      :taken="taken"
      :overrides="(n) => inheritedByName(n)?.label"
      @apply="apply"
      @cancel="editing = undefined"
    />
    <div v-else-if="!disabled">
      <Button
        type="button"
        severity="secondary"
        icon="ti ti-plus"
        :label="t('access.rateLimits.add')"
        @click="editing = -1"
      />
    </div>
  </div>
</template>
