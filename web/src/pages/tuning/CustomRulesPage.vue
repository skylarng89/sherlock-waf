<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { useWriteFlow } from '@/pages/sites/lib/useWriteFlow'
import SiteTabs from '@/pages/sites/SiteTabs.vue'
import WriteBanners from '@/pages/sites/WriteBanners.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import { RESERVED_RULE_IDS } from './lib'
import SecLangEditor from './SecLangEditor.vue'

type Validation = components['schemas']['CustomRulesValidation']
type Issue = Validation['issues'][number]

const VALIDATE_DELAY_MS = 600

const { t } = useI18n()
const route = useRoute()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()
const siteId = computed(() => String(route.params.site))
const canWrite = computed(() => session.can('config:write'))
const uid = useId()
const labelId = `cr-${uid}-label`
const helpId = `cr-${uid}-help`

const state = ref<'loading' | 'ready' | 'missing' | 'error'>('loading')
const saved = ref('')
const text = ref('')
const etag = ref<string>()
const source = ref('none')
const range = ref<{ min: number; max: number }>({ ...RESERVED_RULE_IDS })
const validation = ref<Validation>()
const checking = ref(false)
const checkFailed = ref(false)
const busy = ref(false)
const editor = ref<InstanceType<typeof SecLangEditor>>()

const form = useFormErrors({ known: ['custom_rules'] })
const flow = useWriteFlow({ form, rebase: () => ({ prefixes: [] }) })

const dirty = computed(() => text.value !== saved.value)
const issues = computed<Issue[]>(() => validation.value?.issues ?? [])
const issueLines = computed(() => issues.value.map((i) => i.line).filter((l) => l > 0))
const stale = computed(() => validation.value === undefined || checking.value)
const canSave = computed(
  () => canWrite.value && dirty.value && !busy.value && !stale.value && validation.value?.valid,
)
const title = computed(() => siteId.value)

let timer: ReturnType<typeof setTimeout> | undefined
let seq = 0

async function load() {
  state.value = 'loading'
  flow.reset()
  try {
    const res = await call(
      client.GET('/sites/{site}/custom-rules', { params: { path: { site: siteId.value } } }),
      { toast: false },
    )
    saved.value = text.value = res.data.rules
    source.value = res.data.source
    etag.value = res.etag
    range.value = {
      min: res.data.reserved_id_range?.min ?? RESERVED_RULE_IDS.min,
      max: res.data.reserved_id_range?.max ?? RESERVED_RULE_IDS.max,
    }
    validation.value = undefined
    state.value = 'ready'
    if (text.value.trim()) void validate()
  } catch (e) {
    if (!isApiError(e)) throw e
    state.value = e.kind === 'not_found' ? 'missing' : 'error'
  }
}
onMounted(load)
onBeforeUnmount(() => timer && clearTimeout(timer))

async function validate() {
  if (timer) clearTimeout(timer)
  const mine = ++seq
  checking.value = true
  checkFailed.value = false
  try {
    const res = await call(
      client.POST('/sites/{site}/custom-rules/validate', {
        params: { path: { site: siteId.value } },
        body: { rules: text.value },
      }),
      { toast: false },
    )
    // A newer edit has already started another check; ignore this stale answer.
    if (mine === seq) validation.value = res.data
  } catch (e) {
    if (!isApiError(e)) throw e
    if (mine === seq) {
      validation.value = undefined
      checkFailed.value = true
    }
  } finally {
    if (mine === seq) checking.value = false
  }
}

watch(text, () => {
  if (state.value !== 'ready') return
  validation.value = undefined
  if (timer) clearTimeout(timer)
  timer = setTimeout(() => void validate(), VALIDATE_DELAY_MS)
})

async function save() {
  if (!etag.value) {
    flow.precondition.value = true
    return
  }
  busy.value = true
  flow.reset()
  try {
    const res = await call(
      client.PUT('/sites/{site}/custom-rules', {
        params: { path: { site: siteId.value }, header: ifMatch(etag.value) },
        body: { rules: text.value },
      }),
      { toast: false },
    )
    etag.value = res.etag ?? etag.value
    saved.value = text.value
    source.value = text.value.trim() ? 'site' : source.value
    toasts.success(t('tuning.customRules.saved'))
  } catch (e) {
    flow.handle(e)
    if (isApiError(e) && e.kind === 'validation') void validate()
  } finally {
    busy.value = false
  }
}

function revert() {
  text.value = saved.value
}

const lineLabel = (i: Issue) =>
  i.line > 0 ? t('tuning.customRules.line', { line: i.line }) : t('tuning.customRules.wholeInput')
</script>

<template>
  <SkPageHeader
    :title="t('tuning.customRules.title')"
    :description="t('tuning.customRules.description', { min: range.min, max: range.max })"
    :breadcrumbs="[{ label: t('sites.title'), to: '/sites' }, { label: title }]"
  />

  <p v-if="state === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="state === 'missing' || state === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    {{ state === 'missing' ? t('sites.notFound') : t('tuning.customRules.loadFailed') }}
    <Button :label="t('common.actions.retry')" severity="secondary" @click="load" />
  </div>
  <template v-else>
    <SiteTabs :site="siteId" />
    <WriteBanners
      class="mb-4"
      :stale="flow.stale.value"
      :precondition="flow.precondition.value"
      :unmatched="form.unmatched.value"
      @reload="load"
    />
    <p v-if="!canWrite" class="mb-3 text-sk-muted">
      <i class="ti ti-lock" aria-hidden="true" /> {{ t('tuning.customRules.readOnly') }}
    </p>
    <p v-if="source === 'global'" class="mb-3 text-sk-muted" data-testid="source-note">
      <i class="ti ti-info-circle" aria-hidden="true" /> {{ t('tuning.customRules.sourceGlobal') }}
    </p>
    <p v-else-if="source === 'none' && !text" class="mb-3 text-sk-muted">
      {{ t('tuning.customRules.sourceNone') }}
    </p>

    <form class="flex flex-col gap-3" novalidate @submit.prevent="save">
      <div>
        <span :id="labelId" class="mb-1 block font-medium">
          {{ t('tuning.customRules.editorLabel') }}
        </span>
        <p :id="helpId" class="mb-2 text-sm text-sk-muted">
          {{ t('tuning.customRules.editorHelp') }}
        </p>
        <SecLangEditor
          ref="editor"
          v-model="text"
          :readonly="!canWrite"
          :labelledby="labelId"
          :describedby="helpId"
          :issue-lines="issueLines"
        />
        <p v-if="form.errorFor('custom_rules')" role="alert" class="mt-2 text-sk-danger">
          {{ form.errorFor('custom_rules') }}
        </p>
      </div>

      <div role="status" aria-live="polite" data-testid="validation-status">
        <p v-if="checking">{{ t('tuning.customRules.validating') }}…</p>
        <p v-else-if="checkFailed" class="text-sk-danger">
          <i class="ti ti-alert-triangle" aria-hidden="true" />
          {{ t('tuning.customRules.validateFailed') }}
        </p>
        <p v-else-if="validation?.valid" class="text-sk-success">
          <i class="ti ti-circle-check" aria-hidden="true" />
          {{
            validation.rule_ids.length
              ? t('tuning.customRules.valid', { ids: validation.rule_ids.join(', ') })
              : t('tuning.customRules.validNoIds')
          }}
        </p>
        <p v-else-if="validation" class="text-sk-danger">
          <i class="ti ti-circle-x" aria-hidden="true" />
          {{ t('tuning.customRules.invalid', { count: issues.length }) }}
        </p>
      </div>

      <section v-if="issues.length" aria-labelledby="cr-issues" data-testid="issues">
        <h2 id="cr-issues" class="mb-1 text-lg font-semibold">
          {{ t('tuning.customRules.issues') }}
        </h2>
        <ul class="flex flex-col gap-1">
          <li
            v-for="(i, n) in issues"
            :key="n"
            class="flex flex-wrap items-baseline gap-2 rounded-sk border border-sk-danger bg-sk-danger-bg p-2 text-sk-danger"
          >
            <button
              v-if="i.line > 0"
              type="button"
              class="font-mono underline"
              :aria-label="t('tuning.customRules.goToLine', { line: i.line })"
              @click="editor?.goToLine(i.line)"
            >
              {{ lineLabel(i) }}
            </button>
            <span v-else class="font-mono">{{ lineLabel(i) }}</span>
            <strong>{{ t(`tuning.customRules.code.${i.code}`) }}</strong>
            <span>{{ i.message }}</span>
          </li>
        </ul>
      </section>

      <div class="flex flex-wrap items-center gap-2">
        <Button
          type="button"
          :label="t('tuning.customRules.validate')"
          severity="secondary"
          :disabled="checking"
          @click="validate"
        />
        <template v-if="canWrite">
          <Button
            type="submit"
            :label="t('tuning.customRules.save')"
            :disabled="!canSave"
            :loading="busy"
          />
          <Button
            type="button"
            :label="t('tuning.customRules.revert')"
            severity="secondary"
            :disabled="!dirty || busy"
            @click="revert"
          />
          <span v-if="dirty" class="text-sm text-sk-muted">{{
            t('tuning.customRules.dirty')
          }}</span>
        </template>
      </div>
    </form>
  </template>
</template>
