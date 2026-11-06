<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import ListControl from '@/pages/sites/controls/ListControl.vue'
import NumberControl from '@/pages/sites/controls/NumberControl.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import FintechBaseline from '@/pages/sites/FintechBaseline.vue'
import { clone, getAt, mergePatch } from '@/pages/sites/lib/json'
import { useSiteContext } from '@/pages/sites/lib/useSiteContext'
import { useWriteFlow } from '@/pages/sites/lib/useWriteFlow'
import SiteTabs from '@/pages/sites/SiteTabs.vue'
import WriteBanners from '@/pages/sites/WriteBanners.vue'
import { controlClass } from '@/pages/sites/controls/classes'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import {
  BUILTIN,
  customDetector,
  DLP_ACTIONS,
  DLP_DEFAULTS,
  normaliseDlp,
  pruneDetect,
  validateDlp,
  type DlpPattern,
  type DlpPolicy,
  type FieldErrors,
} from './policy'

const { t } = useI18n()
const route = useRoute()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()
const siteId = computed(() => String(route.params.site))
const ctx = useSiteContext(() => siteId.value)
const canWrite = computed(() => session.can('config:write'))

const dlp = ref<DlpPolicy>({})
const patterns = ref<DlpPattern[]>([])
const baseline = ref<DlpPolicy>()
const busy = ref(false)
const clientErrors = ref<FieldErrors>({})

// The pattern fields exist once per row, so the list of fields that render an error is
// computed when an error arrives.
const form = useFormErrors({
  get known() {
    return [
      'enabled',
      'detect',
      'custom_patterns',
      'action',
      'content_types',
      'max_body_bytes',
      ...patterns.value.flatMap((_, i) => [
        `custom_patterns.${i}.name`,
        `custom_patterns.${i}.pattern`,
      ]),
    ]
  },
})
const flow = useWriteFlow({
  form,
  rebase: () => ({
    prefixes: [`/sites/${ctx.index.value}/policy/dlp`],
    lists: ['content_types', 'detect'],
  }),
})

const title = computed(() => ctx.site.value?.name || siteId.value)
const sitePolicy = computed(() => ctx.site.value?.policy)
const inherited = computed(() => (ctx.defaults.value.dlp ?? {}) as DlpPolicy)
const mode = computed(() =>
  String(sitePolicy.value?.mode ?? getAt(ctx.defaults.value, 'mode') ?? 'detect'),
)
/** What the site scans with now: its own list, else the inherited one, else the built-in. */
const effectiveDetect = computed(
  () => dlp.value.detect ?? inherited.value.detect ?? [DLP_DEFAULTS.detect],
)
/** Patterns a `custom:<name>` detector can refer to: this level's, else the inherited ones. */
const availablePatterns = computed(() =>
  patterns.value.length ? patterns.value : (inherited.value.custom_patterns ?? []),
)

const pick = <T extends string>(values: readonly T[], prefix: string) =>
  values.map((value) => ({ value, label: t(`${prefix}.${value}`) }))

function note(own: unknown, inheritedValue: unknown, builtin: string): string {
  if (own !== undefined) return ''
  return inheritedValue !== undefined
    ? t('dlp.inherited', { value: String(inheritedValue) })
    : t('dlp.builtin', { value: builtin })
}
const withNote = (help: string, extra: string) => [help, extra].filter(Boolean).join(' ')
const err = (key: string) =>
  form.errorFor(key) ||
  (clientErrors.value[key] ? t(`dlp.errors.${clientErrors.value[key]}`) : undefined)

function current(): DlpPolicy | undefined {
  const next: DlpPolicy = { ...dlp.value, custom_patterns: patterns.value.map((p) => ({ ...p })) }
  // A custom detector must name a pattern that still exists here or one this site inherits.
  if (next.detect) next.detect = pruneDetect(next.detect, availablePatterns.value)
  if (next.content_types?.length === 0) delete next.content_types
  return normaliseDlp(next)
}

async function load() {
  flow.reset()
  clientErrors.value = {}
  await ctx.load()
  if (ctx.site.value) {
    const server = clone(ctx.site.value.policy?.dlp ?? {})
    dlp.value = server
    patterns.value = server.custom_patterns ?? []
    baseline.value = normaliseDlp(server)
  }
}
onMounted(load)

function set<K extends keyof DlpPolicy>(key: K, value: DlpPolicy[K] | undefined) {
  form.clear(key)
  clientErrors.value = Object.fromEntries(
    Object.entries(clientErrors.value).filter(([k]) => k !== key),
  )
  dlp.value = { ...dlp.value, [key]: value }
}
function toggleDetector(id: string, on: boolean) {
  const base = effectiveDetect.value.filter((d) => d !== id)
  set('detect', on ? [...base, id] : base)
}
const addPattern = () => (patterns.value = [...patterns.value, { name: '', pattern: '' }])
const removePattern = (i: number) => (patterns.value = patterns.value.filter((_, n) => n !== i))
const patchPattern = (i: number, change: Partial<DlpPattern>) =>
  (patterns.value = patterns.value.map((p, n) => (n === i ? { ...p, ...change } : p)))

const wrap = (p: DlpPolicy | undefined) => (p ? { policy: { dlp: p } } : {})

async function save() {
  flow.reset()
  const next = current()
  clientErrors.value = validateDlp(next)
  if (Object.keys(clientErrors.value).length) return
  const body = mergePatch(wrap(baseline.value), wrap(next))
  if (!body) {
    toasts.info(t('sites.noChanges'))
    return
  }
  if (!ctx.etag.value) {
    flow.precondition.value = true
    return
  }
  busy.value = true
  try {
    const res = await call(
      client.PATCH('/sites/{site}', {
        params: { path: { site: siteId.value }, header: ifMatch(ctx.etag.value) },
        headers: { 'Content-Type': 'application/merge-patch+json' },
        body,
      }),
      { toast: false },
    )
    ctx.etag.value = res.etag ?? ctx.etag.value
    baseline.value = next
    toasts.success(t('dlp.saved'))
  } catch (e) {
    flow.handle(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader
    :title="title"
    :description="t('dlp.description')"
    :breadcrumbs="[{ label: t('sites.title'), to: '/sites' }, { label: title }]"
  />

  <p v-if="ctx.state.value === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="ctx.state.value === 'missing'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    {{ t('sites.notFound') }}
    <RouterLink to="/sites" class="underline">{{ t('sites.backToList') }}</RouterLink>
  </div>
  <div
    v-else-if="ctx.state.value === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    {{ t('sites.loadFailed') }}
    <Button :label="t('common.actions.retry')" severity="secondary" @click="load" />
  </div>
  <template v-else>
    <SiteTabs :site="siteId" />
    <p v-if="!canWrite" role="status" class="mb-4 text-sk-muted">
      <i class="ti ti-lock" aria-hidden="true" />
      {{ t('dlp.readOnly') }}
    </p>
    <p
      v-if="mode !== 'block'"
      role="status"
      class="mb-4 max-w-3xl rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
      data-testid="mode-notice"
    >
      <i class="ti ti-alert-triangle" aria-hidden="true" />
      {{ mode === 'off' ? t('dlp.mode.off') : t('dlp.mode.detect') }}
    </p>

    <FintechBaseline
      :site-id="siteId"
      :policy="sitePolicy"
      :defaults="ctx.defaults.value"
      :etag="ctx.etag.value"
      :can-write="canWrite"
      @applied="load"
    />

    <form class="flex max-w-3xl flex-col gap-6" novalidate @submit.prevent="save">
      <WriteBanners
        :stale="flow.stale.value"
        :precondition="flow.precondition.value"
        :unmatched="form.unmatched.value"
        @reload="load"
      />

      <section class="flex flex-col gap-4" aria-labelledby="dlp-general">
        <h2 id="dlp-general" class="text-lg font-semibold">{{ t('dlp.sections.general') }}</h2>
        <p class="text-sk-muted" data-testid="dlp-privacy">{{ t('dlp.privacy') }}</p>
        <SkFormField
          :label="t('dlp.enabled.label')"
          :help="note(dlp.enabled, inherited.enabled, 'off')"
          :error="err('enabled')"
        >
          <template #default="{ attrs }">
            <SwitchControl
              v-bind="attrs"
              :model-value="dlp.enabled === true"
              :label="t('dlp.enabled.switch')"
              :disabled="!canWrite"
              @update:model-value="set('enabled', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('dlp.action.label')"
          :help="
            withNote(t('dlp.action.help'), note(dlp.action, inherited.action, DLP_DEFAULTS.action))
          "
          :error="err('action')"
        >
          <template #default="{ attrs }">
            <SelectControl
              v-bind="attrs"
              :model-value="dlp.action"
              :options="pick(DLP_ACTIONS, 'dlp.action')"
              :empty-label="
                t('common.inherited.from', { source: t('common.inherited.source.defaults') })
              "
              :disabled="!canWrite"
              @update:model-value="set('action', $event)"
            />
          </template>
        </SkFormField>
      </section>

      <section class="flex flex-col gap-3" aria-labelledby="dlp-detect">
        <h2 id="dlp-detect" class="text-lg font-semibold">{{ t('dlp.sections.detect') }}</h2>
        <fieldset class="flex flex-col gap-2" :aria-describedby="'dlp-detect-help'">
          <legend class="sr-only">{{ t('dlp.sections.detect') }}</legend>
          <p id="dlp-detect-help" class="text-sk-muted">
            {{
              withNote(
                t('dlp.detect.help'),
                note(dlp.detect, inherited.detect?.join(', '), DLP_DEFAULTS.detect),
              )
            }}
          </p>
          <label v-for="id in BUILTIN" :key="id" class="flex items-center gap-2">
            <input
              type="checkbox"
              class="size-4 accent-[var(--sk-accent)]"
              :checked="effectiveDetect.includes(id)"
              :disabled="!canWrite"
              :data-testid="`detect-${id}`"
              @change="toggleDetector(id, ($event.target as HTMLInputElement).checked)"
            />
            {{ t(`dlp.detect.${id}`) }}
          </label>
          <label
            v-for="cp in availablePatterns.filter((p) => p.name)"
            :key="cp.name"
            class="flex items-center gap-2"
          >
            <input
              type="checkbox"
              class="size-4 accent-[var(--sk-accent)]"
              :checked="effectiveDetect.includes(customDetector(cp.name))"
              :disabled="!canWrite"
              :data-testid="`detect-custom-${cp.name}`"
              @change="
                toggleDetector(customDetector(cp.name), ($event.target as HTMLInputElement).checked)
              "
            />
            {{ t('dlp.detect.custom', { name: cp.name }) }}
          </label>
          <p v-if="!effectiveDetect.length" role="status" class="text-sk-warning">
            {{ t('dlp.detect.none') }}
          </p>
          <p v-if="err('detect')" role="alert" class="text-sk-danger">{{ err('detect') }}</p>
          <div v-if="canWrite && dlp.detect !== undefined">
            <Button
              type="button"
              severity="secondary"
              :label="t('common.inherited.from', { source: t('common.inherited.source.defaults') })"
              @click="set('detect', undefined)"
            />
          </div>
        </fieldset>
      </section>

      <section class="flex flex-col gap-4" aria-labelledby="dlp-patterns">
        <h2 id="dlp-patterns" class="text-lg font-semibold">{{ t('dlp.sections.patterns') }}</h2>
        <p class="text-sk-muted">{{ t('dlp.patterns.help') }}</p>
        <p v-if="err('custom_patterns')" role="alert" class="text-sk-danger">
          {{ err('custom_patterns') }}
        </p>
        <p v-if="!patterns.length" class="text-sk-muted">{{ t('dlp.patterns.empty') }}</p>
        <fieldset
          v-for="(cp, i) in patterns"
          :key="i"
          class="flex flex-col gap-3 rounded-sk border border-sk-border p-4"
          :data-testid="`dlp-pattern-${i}`"
        >
          <legend class="px-1 font-medium">{{ t('dlp.patterns.legend', { n: i + 1 }) }}</legend>
          <SkFormField
            :label="t('dlp.patterns.name.label')"
            :help="t('dlp.patterns.name.help')"
            :error="err(`custom_patterns.${i}.name`)"
            required
          >
            <template #default="{ attrs, invalid }">
              <TextControl
                v-bind="attrs"
                mono
                :model-value="cp.name"
                :disabled="!canWrite"
                :aria-invalid="invalid ? 'true' : undefined"
                @update:model-value="patchPattern(i, { name: $event })"
              />
            </template>
          </SkFormField>
          <SkFormField
            :label="t('dlp.patterns.pattern.label')"
            :help="t('dlp.patterns.pattern.help')"
            :error="err(`custom_patterns.${i}.pattern`)"
            required
          >
            <template #default="{ attrs, invalid }">
              <textarea
                v-bind="attrs"
                :class="[controlClass, 'font-mono']"
                rows="2"
                :value="cp.pattern"
                :disabled="!canWrite"
                :aria-invalid="invalid ? 'true' : undefined"
                spellcheck="false"
                @input="patchPattern(i, { pattern: ($event.target as HTMLTextAreaElement).value })"
              />
            </template>
          </SkFormField>
          <div v-if="canWrite">
            <Button
              type="button"
              severity="secondary"
              icon="ti ti-trash"
              :label="t('common.actions.delete')"
              :aria-label="t('dlp.patterns.remove', { n: i + 1 })"
              @click="removePattern(i)"
            />
          </div>
        </fieldset>
        <div v-if="canWrite">
          <Button
            type="button"
            severity="secondary"
            icon="ti ti-plus"
            :label="t('dlp.patterns.add')"
            @click="addPattern"
          />
        </div>
      </section>

      <section class="flex flex-col gap-4" aria-labelledby="dlp-scope">
        <h2 id="dlp-scope" class="text-lg font-semibold">{{ t('dlp.sections.scope') }}</h2>
        <SkFormField
          :label="t('dlp.contentTypes.label')"
          :help="
            withNote(
              t('dlp.contentTypes.help'),
              note(
                dlp.content_types,
                inherited.content_types?.join(', '),
                DLP_DEFAULTS.content_types,
              ),
            )
          "
          :error="err('content_types')"
        >
          <template #default="{ attrs, invalid }">
            <ListControl
              v-bind="attrs"
              :model-value="dlp.content_types"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="set('content_types', $event.length ? $event : undefined)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('dlp.maxBody.label')"
          :help="
            withNote(
              t('dlp.maxBody.help'),
              note(
                dlp.max_body_bytes,
                inherited.max_body_bytes,
                String(DLP_DEFAULTS.max_body_bytes),
              ),
            )
          "
          :error="err('max_body_bytes')"
        >
          <template #default="{ attrs, invalid }">
            <NumberControl
              v-bind="attrs"
              :model-value="dlp.max_body_bytes"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="set('max_body_bytes', $event)"
            />
          </template>
        </SkFormField>
      </section>

      <div v-if="canWrite">
        <Button type="submit" :label="t('common.actions.save')" :loading="busy" :disabled="busy" />
      </div>
    </form>
  </template>
</template>
