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
import FintechBaseline from '@/pages/sites/FintechBaseline.vue'
import { clone, getAt, mergePatch } from '@/pages/sites/lib/json'
import { useSiteContext } from '@/pages/sites/lib/useSiteContext'
import { useWriteFlow } from '@/pages/sites/lib/useWriteFlow'
import SiteTabs from '@/pages/sites/SiteTabs.vue'
import WriteBanners from '@/pages/sites/WriteBanners.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import {
  draftToEndpoint,
  emptyEndpoint,
  endpointToDraft,
  LOGIN_ACTIONS,
  LOGIN_DEFAULTS,
  LOGIN_METHODS,
  normaliseLogin,
  validateLogin,
  type EndpointDraft,
  type FieldErrors,
  type LoginPolicy,
} from './policy'

const { t } = useI18n()
const route = useRoute()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()
const siteId = computed(() => String(route.params.site))
const ctx = useSiteContext(() => siteId.value)
const canWrite = computed(() => session.can('config:write'))

const login = ref<LoginPolicy>({})
const endpoints = ref<EndpointDraft[]>([])
const baseline = ref<LoginPolicy>()
const busy = ref(false)
const clientErrors = ref<FieldErrors>({})

// The endpoint fields exist once per row, so the list of fields that render an error is
// computed when an error arrives.
const form = useFormErrors({
  get known() {
    return [
      'enabled',
      'endpoints',
      'thresholds',
      'thresholds.per_ip',
      'thresholds.per_username',
      'thresholds.per_device',
      'thresholds.window',
      'action',
      ...endpoints.value.flatMap((_, i) =>
        ['path', 'method', 'username_field', 'failure_statuses'].map((f) => `endpoints.${i}.${f}`),
      ),
    ]
  },
})
const flow = useWriteFlow({
  form,
  rebase: () => ({
    prefixes: [`/sites/${ctx.index.value}/policy/login_protection`],
  }),
})

const title = computed(() => ctx.site.value?.name || siteId.value)
const sitePolicy = computed(() => ctx.site.value?.policy)
const inheritedLogin = computed(() => (ctx.defaults.value.login_protection ?? {}) as LoginPolicy)
const mode = computed(() =>
  String(sitePolicy.value?.mode ?? getAt(ctx.defaults.value, 'mode') ?? 'detect'),
)
const inheritedEndpointsText = computed(() => {
  const list = inheritedLogin.value.endpoints ?? []
  if (!list.length) return t('login.endpoints.empty')
  return t('login.inherited', {
    value: list.map((e) => `${e.method ?? 'POST'} ${e.path}`).join(', '),
  })
})
const showEmptyWarning = computed(
  () =>
    login.value.enabled === true &&
    endpoints.value.length === 0 &&
    !(inheritedLogin.value.endpoints?.length ?? 0),
)

const pick = <T extends string>(values: readonly T[], prefix: string) =>
  values.map((value) => ({ value, label: t(`${prefix}.${value}`) }))
const methodOptions = LOGIN_METHODS.map((value) => ({ value: String(value), label: value }))

/** "Inherited: x" / "Default: y" for a field the site does not set. */
function note(own: unknown, inherited: unknown, builtin: string): string {
  if (own !== undefined) return ''
  return inherited !== undefined
    ? t('login.inherited', { value: String(inherited) })
    : t('login.builtin', { value: builtin })
}
const withNote = (help: string, extra: string) => [help, extra].filter(Boolean).join(' ')

const err = (key: string) =>
  form.errorFor(key) ||
  (clientErrors.value[key] ? t(`login.errors.${clientErrors.value[key]}`) : undefined)

function current(): LoginPolicy | undefined {
  return normaliseLogin({ ...login.value, endpoints: endpoints.value.map(draftToEndpoint) })
}

async function load() {
  flow.reset()
  clientErrors.value = {}
  await ctx.load()
  if (ctx.site.value) {
    const server = clone(ctx.site.value.policy?.login_protection ?? {})
    login.value = server
    endpoints.value = (server.endpoints ?? []).map(endpointToDraft)
    baseline.value = normaliseLogin(server)
  }
}
onMounted(load)

function set<K extends keyof LoginPolicy>(key: K, value: LoginPolicy[K] | undefined) {
  form.clear(key)
  login.value = { ...login.value, [key]: value }
}
function setThreshold(key: 'per_ip' | 'per_username' | 'per_device' | 'window', value: unknown) {
  form.clear('thresholds')
  clientErrors.value = Object.fromEntries(
    Object.entries(clientErrors.value).filter(([k]) => k !== `thresholds.${key}`),
  )
  login.value = { ...login.value, thresholds: { ...login.value.thresholds, [key]: value } }
}
const addEndpoint = () => (endpoints.value = [...endpoints.value, emptyEndpoint()])
const removeEndpoint = (i: number) => (endpoints.value = endpoints.value.filter((_, n) => n !== i))
const patchEndpoint = (i: number, change: Partial<EndpointDraft>) =>
  (endpoints.value = endpoints.value.map((e, n) => (n === i ? { ...e, ...change } : e)))

const wrap = (p: LoginPolicy | undefined) => (p ? { policy: { login_protection: p } } : {})

async function save() {
  flow.reset()
  const next = current()
  clientErrors.value = validateLogin(next, endpoints.value, LOGIN_METHODS)
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
    toasts.success(t('login.saved'))
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
    :description="t('login.description')"
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
      {{ t('login.readOnly') }}
    </p>
    <p
      v-if="mode !== 'block'"
      role="status"
      class="mb-4 max-w-3xl rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
      data-testid="mode-notice"
    >
      <i class="ti ti-alert-triangle" aria-hidden="true" />
      {{ mode === 'off' ? t('login.mode.off') : t('login.mode.detect') }}
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

      <section class="flex flex-col gap-4" aria-labelledby="login-general">
        <h2 id="login-general" class="text-lg font-semibold">{{ t('login.sections.general') }}</h2>
        <p class="text-sk-muted" data-testid="login-privacy">{{ t('login.privacy') }}</p>
        <SkFormField
          :label="t('login.enabled.label')"
          :help="note(login.enabled, inheritedLogin.enabled, 'off')"
          :error="err('enabled')"
        >
          <template #default="{ attrs }">
            <SwitchControl
              v-bind="attrs"
              :model-value="login.enabled === true"
              :label="t('login.enabled.switch')"
              :disabled="!canWrite"
              @update:model-value="set('enabled', $event)"
            />
          </template>
        </SkFormField>
        <p v-if="showEmptyWarning" role="status" class="text-sk-warning" data-testid="no-endpoints">
          <i class="ti ti-alert-triangle" aria-hidden="true" />
          {{ t('login.noEndpoints') }}
        </p>
      </section>

      <section class="flex flex-col gap-4" aria-labelledby="login-endpoints">
        <h2 id="login-endpoints" class="text-lg font-semibold">
          {{ t('login.sections.endpoints') }}
        </h2>
        <p class="text-sk-muted">{{ t('login.endpoints.help') }}</p>
        <p v-if="err('endpoints')" role="alert" class="text-sk-danger">{{ err('endpoints') }}</p>
        <p v-if="!endpoints.length" class="text-sk-muted">
          {{ inheritedEndpointsText }}
        </p>
        <fieldset
          v-for="(ep, i) in endpoints"
          :key="i"
          class="flex flex-col gap-3 rounded-sk border border-sk-border p-4"
          :data-testid="`login-endpoint-${i}`"
        >
          <legend class="px-1 font-medium">{{ t('login.endpoints.legend', { n: i + 1 }) }}</legend>
          <SkFormField
            :label="t('login.endpoints.path.label')"
            :help="t('login.endpoints.path.help')"
            :error="err(`endpoints.${i}.path`)"
            required
          >
            <template #default="{ attrs, invalid }">
              <TextControl
                v-bind="attrs"
                mono
                :model-value="ep.path"
                :disabled="!canWrite"
                :aria-invalid="invalid ? 'true' : undefined"
                @update:model-value="patchEndpoint(i, { path: $event })"
              />
            </template>
          </SkFormField>
          <SkFormField
            :label="t('login.endpoints.method.label')"
            :error="err(`endpoints.${i}.method`)"
          >
            <template #default="{ attrs }">
              <SelectControl
                v-bind="attrs"
                :model-value="ep.method"
                :options="methodOptions"
                :empty-label="t('login.endpoints.method.default')"
                :disabled="!canWrite"
                @update:model-value="patchEndpoint(i, { method: $event ?? '' })"
              />
            </template>
          </SkFormField>
          <SkFormField
            :label="t('login.endpoints.username.label')"
            :help="t('login.endpoints.username.help')"
            :error="err(`endpoints.${i}.username_field`)"
            required
          >
            <template #default="{ attrs, invalid }">
              <TextControl
                v-bind="attrs"
                mono
                :model-value="ep.usernameField"
                :disabled="!canWrite"
                :aria-invalid="invalid ? 'true' : undefined"
                @update:model-value="patchEndpoint(i, { usernameField: $event })"
              />
            </template>
          </SkFormField>
          <SkFormField
            :label="t('login.endpoints.statuses.label')"
            :help="t('login.endpoints.statuses.help')"
            :error="err(`endpoints.${i}.failure_statuses`)"
          >
            <template #default="{ attrs, invalid }">
              <TextControl
                v-bind="attrs"
                mono
                :model-value="ep.failureStatuses"
                :disabled="!canWrite"
                :aria-invalid="invalid ? 'true' : undefined"
                @update:model-value="patchEndpoint(i, { failureStatuses: $event })"
              />
            </template>
          </SkFormField>
          <div v-if="canWrite">
            <Button
              type="button"
              severity="secondary"
              icon="ti ti-trash"
              :label="t('common.actions.delete')"
              :aria-label="t('login.endpoints.remove', { n: i + 1 })"
              @click="removeEndpoint(i)"
            />
          </div>
        </fieldset>
        <div v-if="canWrite">
          <Button
            type="button"
            severity="secondary"
            icon="ti ti-plus"
            :label="t('login.endpoints.add')"
            @click="addEndpoint"
          />
        </div>
      </section>

      <section class="flex flex-col gap-4" aria-labelledby="login-limits">
        <h2 id="login-limits" class="text-lg font-semibold">{{ t('login.sections.limits') }}</h2>
        <p class="text-sk-muted">{{ t('login.thresholds.help') }}</p>
        <p v-if="form.errorFor('thresholds')" role="alert" class="text-sk-danger">
          {{ form.errorFor('thresholds') }}
        </p>
        <SkFormField
          :label="t('login.thresholds.perIp.label')"
          :help="
            note(
              login.thresholds?.per_ip,
              inheritedLogin.thresholds?.per_ip,
              String(LOGIN_DEFAULTS.per_ip),
            )
          "
          :error="err('thresholds.per_ip')"
        >
          <template #default="{ attrs, invalid }">
            <NumberControl
              v-bind="attrs"
              :model-value="login.thresholds?.per_ip"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="setThreshold('per_ip', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('login.thresholds.perUsername.label')"
          :help="
            note(
              login.thresholds?.per_username,
              inheritedLogin.thresholds?.per_username,
              String(LOGIN_DEFAULTS.per_username),
            )
          "
          :error="err('thresholds.per_username')"
        >
          <template #default="{ attrs, invalid }">
            <NumberControl
              v-bind="attrs"
              :model-value="login.thresholds?.per_username"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="setThreshold('per_username', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('login.thresholds.perDevice.label')"
          :help="
            note(
              login.thresholds?.per_device,
              inheritedLogin.thresholds?.per_device,
              String(LOGIN_DEFAULTS.per_device),
            )
          "
          :error="err('thresholds.per_device')"
        >
          <template #default="{ attrs, invalid }">
            <NumberControl
              v-bind="attrs"
              :model-value="login.thresholds?.per_device"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="setThreshold('per_device', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('login.thresholds.window.label')"
          :help="
            withNote(
              t('login.thresholds.window.help'),
              note(
                login.thresholds?.window,
                inheritedLogin.thresholds?.window,
                LOGIN_DEFAULTS.window,
              ),
            )
          "
          :error="err('thresholds.window')"
        >
          <template #default="{ attrs, invalid }">
            <TextControl
              v-bind="attrs"
              mono
              :model-value="login.thresholds?.window"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="setThreshold('window', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('login.action.label')"
          :help="
            withNote(
              t('login.action.help'),
              note(login.action, inheritedLogin.action, LOGIN_DEFAULTS.action),
            )
          "
          :error="err('action')"
        >
          <template #default="{ attrs }">
            <SelectControl
              v-bind="attrs"
              :model-value="login.action"
              :options="pick(LOGIN_ACTIONS, 'login.action')"
              :empty-label="
                t('common.inherited.from', { source: t('common.inherited.source.defaults') })
              "
              :disabled="!canWrite"
              @update:model-value="set('action', $event)"
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
