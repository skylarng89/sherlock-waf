<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import NumberControl from '@/pages/sites/controls/NumberControl.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { clone, mergePatch } from '@/pages/sites/lib/json'
import { useSiteContext } from '@/pages/sites/lib/useSiteContext'
import { useWriteFlow } from '@/pages/sites/lib/useWriteFlow'
import SiteTabs from '@/pages/sites/SiteTabs.vue'
import WriteBanners from '@/pages/sites/WriteBanners.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import { draftToRule, normalise, ruleToDraft, type BotPolicy, type RuleDraft } from './policy'

const { t } = useI18n()
const route = useRoute()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()
const siteId = computed(() => String(route.params.site))
const ctx = useSiteContext(() => siteId.value)
const canWrite = computed(() => session.can('config:write'))

const bot = ref<BotPolicy>({})
const rules = ref<RuleDraft[]>([])
const baseline = ref<BotPolicy>()
const busy = ref(false)

const form = useFormErrors({
  known: [
    'enabled',
    'challenge',
    'difficulty',
    'clearance_ttl',
    'site_key',
    'verified_bots',
    'rules',
  ],
})
const flow = useWriteFlow({
  form,
  rebase: () => ({ prefixes: [`/sites/${ctx.index.value}/policy/bot`], lists: ['rules'] }),
})

const title = computed(() => ctx.site.value?.name || siteId.value)
const usesProvider = computed(() => bot.value.challenge && bot.value.challenge !== 'pow')

const CHALLENGES = ['pow', 'turnstile', 'hcaptcha'] as const
const VERIFIED = ['allow', 'challenge', 'block'] as const
const ACTIONS = ['challenge', 'block', 'allow'] as const
const pick = <T extends string>(values: readonly T[], prefix: string) =>
  values.map((value) => ({ value, label: t(`${prefix}.${value}`) }))

function current(): BotPolicy | undefined {
  return normalise({ ...bot.value, rules: rules.value.map(draftToRule) })
}

async function load() {
  flow.reset()
  await ctx.load()
  if (ctx.site.value) {
    const server = clone(ctx.site.value.policy?.bot ?? {})
    bot.value = server
    rules.value = (server.rules ?? []).map(ruleToDraft)
    baseline.value = normalise(server)
  }
}
onMounted(load)

function set<K extends keyof BotPolicy>(key: K, value: BotPolicy[K] | undefined) {
  form.clear(key)
  bot.value = { ...bot.value, [key]: value }
}

function addRule() {
  rules.value = [
    ...rules.value,
    { paths: '', methods: '', countries: '', reputation: false, action: 'challenge' },
  ]
}
function removeRule(index: number) {
  rules.value = rules.value.filter((_, i) => i !== index)
}
function patchRule(index: number, change: Partial<RuleDraft>) {
  rules.value = rules.value.map((r, i) => (i === index ? { ...r, ...change } : r))
}

const wrap = (b: BotPolicy | undefined) => (b ? { policy: { bot: b } } : {})

async function save() {
  flow.reset()
  const next = current()
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
    toasts.success(t('bot.saved'))
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
    :description="t('bot.description')"
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
      {{ t('bot.readOnly') }}
    </p>
    <form class="flex max-w-3xl flex-col gap-6" novalidate @submit.prevent="save">
      <WriteBanners
        :stale="flow.stale.value"
        :precondition="flow.precondition.value"
        :unmatched="form.unmatched.value"
        @reload="load"
      />

      <section class="flex flex-col gap-4" aria-labelledby="bot-general">
        <h2 id="bot-general" class="text-lg font-semibold">{{ t('bot.sections.general') }}</h2>
        <SkFormField :label="t('bot.enabled.label')" :error="form.errorFor('enabled')">
          <template #default="{ attrs }">
            <SwitchControl
              v-bind="attrs"
              :model-value="bot.enabled === true"
              :label="t('bot.enabled.switch')"
              :disabled="!canWrite"
              @update:model-value="set('enabled', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('bot.challenge.label')"
          :help="t('bot.challenge.help')"
          :error="form.errorFor('challenge')"
        >
          <template #default="{ attrs, invalid }">
            <SelectControl
              v-bind="attrs"
              :model-value="bot.challenge ?? 'pow'"
              :options="pick(CHALLENGES, 'bot.challenge.options')"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="set('challenge', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          v-if="!usesProvider"
          :label="t('bot.difficulty.label')"
          :help="t('bot.difficulty.help')"
          :error="form.errorFor('difficulty')"
        >
          <template #default="{ attrs, invalid }">
            <NumberControl
              v-bind="attrs"
              :model-value="bot.difficulty"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="set('difficulty', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          v-else
          :label="t('bot.siteKey.label')"
          :help="t('bot.siteKey.help')"
          :error="form.errorFor('site_key')"
        >
          <template #default="{ attrs, invalid }">
            <TextControl
              v-bind="attrs"
              mono
              :model-value="bot.site_key"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="set('site_key', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('bot.clearanceTtl.label')"
          :help="t('bot.clearanceTtl.help')"
          :error="form.errorFor('clearance_ttl')"
        >
          <template #default="{ attrs, invalid }">
            <TextControl
              v-bind="attrs"
              mono
              :model-value="bot.clearance_ttl"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="set('clearance_ttl', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('bot.verifiedBots.label')"
          :help="t('bot.verifiedBots.help')"
          :error="form.errorFor('verified_bots')"
        >
          <template #default="{ attrs, invalid }">
            <SelectControl
              v-bind="attrs"
              :model-value="bot.verified_bots ?? 'allow'"
              :options="pick(VERIFIED, 'bot.verifiedBots.options')"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="set('verified_bots', $event)"
            />
          </template>
        </SkFormField>
      </section>

      <section class="flex flex-col gap-4" aria-labelledby="bot-rules">
        <h2 id="bot-rules" class="text-lg font-semibold">{{ t('bot.sections.rules') }}</h2>
        <p class="text-sk-muted">{{ t('bot.rules.help') }}</p>
        <p v-if="form.errorFor('rules')" role="alert" class="text-sk-danger">
          {{ form.errorFor('rules') }}
        </p>
        <p v-if="!rules.length" class="text-sk-muted">{{ t('bot.rules.empty') }}</p>
        <fieldset
          v-for="(rule, i) in rules"
          :key="i"
          class="flex flex-col gap-3 rounded-sk border border-sk-border p-4"
          :data-testid="`bot-rule-${i}`"
        >
          <legend class="px-1 font-medium">{{ t('bot.rules.legend', { n: i + 1 }) }}</legend>
          <SkFormField
            :label="t('bot.rules.paths.label')"
            :help="t('bot.rules.paths.help')"
            :error="form.errorFor(`rules.${i}.match.paths`)"
          >
            <template #default="{ attrs }">
              <TextControl
                v-bind="attrs"
                mono
                :model-value="rule.paths"
                :disabled="!canWrite"
                @update:model-value="patchRule(i, { paths: $event })"
              />
            </template>
          </SkFormField>
          <SkFormField
            :label="t('bot.rules.methods.label')"
            :help="t('bot.rules.methods.help')"
            :error="form.errorFor(`rules.${i}.match.methods`)"
          >
            <template #default="{ attrs }">
              <TextControl
                v-bind="attrs"
                mono
                :model-value="rule.methods"
                :disabled="!canWrite"
                @update:model-value="patchRule(i, { methods: $event })"
              />
            </template>
          </SkFormField>
          <SkFormField
            :label="t('bot.rules.countries.label')"
            :help="t('bot.rules.countries.help')"
            :error="form.errorFor(`rules.${i}.match.countries`)"
          >
            <template #default="{ attrs }">
              <TextControl
                v-bind="attrs"
                mono
                :model-value="rule.countries"
                :disabled="!canWrite"
                @update:model-value="patchRule(i, { countries: $event })"
              />
            </template>
          </SkFormField>
          <SwitchControl
            :model-value="rule.reputation"
            :label="t('bot.rules.reputation')"
            :disabled="!canWrite"
            @update:model-value="patchRule(i, { reputation: $event })"
          />
          <SkFormField
            :label="t('bot.rules.action.label')"
            :error="form.errorFor(`rules.${i}.action`)"
          >
            <template #default="{ attrs }">
              <SelectControl
                v-bind="attrs"
                :model-value="rule.action"
                :options="pick(ACTIONS, 'bot.rules.action.options')"
                :disabled="!canWrite"
                @update:model-value="patchRule(i, { action: $event ?? 'challenge' })"
              />
            </template>
          </SkFormField>
          <div v-if="canWrite">
            <Button
              type="button"
              severity="secondary"
              icon="ti ti-trash"
              :label="t('common.actions.delete')"
              :aria-label="t('bot.rules.remove', { n: i + 1 })"
              @click="removeRule(i)"
            />
          </div>
        </fieldset>
        <div v-if="canWrite">
          <Button
            type="button"
            severity="secondary"
            icon="ti ti-plus"
            :label="t('bot.rules.add')"
            @click="addRule"
          />
        </div>
      </section>

      <div v-if="canWrite">
        <Button type="submit" :label="t('common.actions.save')" :loading="busy" :disabled="busy" />
      </div>
    </form>
  </template>
</template>
