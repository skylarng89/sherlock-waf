<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { controlClass } from '@/pages/sites/controls/classes'
import { clone, mergePatch } from '@/pages/sites/lib/json'
import { useSiteContext } from '@/pages/sites/lib/useSiteContext'
import { useWriteFlow } from '@/pages/sites/lib/useWriteFlow'
import SiteTabs from '@/pages/sites/SiteTabs.vue'
import WriteBanners from '@/pages/sites/WriteBanners.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import {
  draftToRule,
  emptyDraft,
  KEY_SOURCES,
  normalise,
  ruleToDraft,
  splitList,
  type ApiPolicy,
  type JwtDraft,
} from './policy'

type Doc = components['schemas']['APIDoc']
type CABundle = components['schemas']['CABundle']
type EndpointList = components['schemas']['APIEndpointList']

const { t } = useI18n()
const route = useRoute()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()
const siteId = computed(() => String(route.params.site))
const ctx = useSiteContext(() => siteId.value)
const canWrite = computed(() => session.can('config:write'))

const api = ref<ApiPolicy>({})
const rules = ref<JwtDraft[]>([])
const requiredPaths = ref('')
const baseline = ref<ApiPolicy>()
const busy = ref(false)
const docs = ref<Doc[]>([])
const bundles = ref<CABundle[]>([])
const endpoints = ref<EndpointList>()
const endpointsError = ref(false)

const form = useFormErrors({
  known: [
    'enabled',
    'openapi_doc_id',
    'unknown_path_action',
    'schema_violation_action',
    'jwt',
    'mtls',
  ],
})
const flow = useWriteFlow({
  form,
  rebase: () => ({ prefixes: [`/sites/${ctx.index.value}/policy/api`], lists: ['jwt'] }),
})

const title = computed(() => ctx.site.value?.name || siteId.value)
const ACTIONS = ['log', 'block'] as const
const pick = <T extends string>(values: readonly T[], prefix: string) =>
  values.map((value) => ({ value, label: t(`${prefix}.${value}`) }))

function current(): ApiPolicy | undefined {
  const mtls = { ...api.value.mtls, required_paths: splitList(requiredPaths.value) }
  return normalise({ ...api.value, jwt: rules.value.map(draftToRule), mtls })
}

async function loadEndpoints() {
  endpoints.value = undefined
  endpointsError.value = false
  const id = api.value.openapi_doc_id
  if (!id) return
  try {
    const res = await call(
      client.GET('/api-docs/{id}/endpoints', {
        params: { path: { id }, query: { site: siteId.value } },
      }),
      { toast: false },
    )
    endpoints.value = res.data
  } catch {
    endpointsError.value = true
  }
}

async function loadAssets() {
  const [d, c] = await Promise.allSettled([
    call(client.GET('/api-docs'), { toast: false }),
    call(client.GET('/ca-bundles'), { toast: false }),
  ])
  if (d.status === 'fulfilled') docs.value = d.value.data.items
  if (c.status === 'fulfilled') bundles.value = c.value.data.items
}

async function load() {
  flow.reset()
  await ctx.load()
  if (ctx.site.value) {
    const server = clone(ctx.site.value.policy?.api ?? {})
    api.value = server
    rules.value = (server.jwt ?? []).map(ruleToDraft)
    requiredPaths.value = (server.mtls?.required_paths ?? []).join(', ')
    baseline.value = normalise(server)
  }
  await Promise.all([loadAssets(), loadEndpoints()])
}
onMounted(load)

function set<K extends keyof ApiPolicy>(key: K, value: ApiPolicy[K] | undefined) {
  form.clear(key)
  api.value = { ...api.value, [key]: value }
}
const addRule = () => (rules.value = [...rules.value, emptyDraft()])
const removeRule = (i: number) => (rules.value = rules.value.filter((_, n) => n !== i))
const patchRule = (i: number, change: Partial<JwtDraft>) =>
  (rules.value = rules.value.map((r, n) => (n === i ? { ...r, ...change } : r)))

const wrap = (a: ApiPolicy | undefined) => (a ? { policy: { api: a } } : {})

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
    toasts.success(t('api.saved'))
    await loadEndpoints()
  } catch (e) {
    flow.handle(e)
  } finally {
    busy.value = false
  }
}

// --- uploads ---
const docDraft = ref({ id: '', name: '', content: '' })
const caDraft = ref({ name: '', pem: '' })
const uploadError = ref('')
const uploading = ref(false)

const problemText = (e: unknown) => (isApiError(e) ? (e.detail ?? e.title) : t('api.uploadFailed'))

async function readFile(event: Event, into: (text: string, name: string) => void) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (file) into(await file.text(), file.name)
}

async function uploadDoc() {
  uploadError.value = ''
  uploading.value = true
  try {
    const d = docDraft.value
    const res = await call(
      client.PUT('/api-docs/{id}', {
        params: { path: { id: d.id } },
        body: { name: d.name || d.id, content: d.content },
      }),
      { toast: false },
    )
    toasts.success(t('api.docs.uploaded', { count: res.data.endpoint_count }))
    docDraft.value = { id: '', name: '', content: '' }
    await loadAssets()
    set('openapi_doc_id', res.data.id)
    await loadEndpoints()
  } catch (e) {
    uploadError.value = problemText(e)
  } finally {
    uploading.value = false
  }
}

async function uploadCA() {
  uploadError.value = ''
  uploading.value = true
  try {
    const res = await call(
      client.POST('/ca-bundles', {
        body: { name: caDraft.value.name, certificates_pem: caDraft.value.pem },
      }),
      { toast: false },
    )
    toasts.success(t('api.mtls.uploaded'))
    caDraft.value = { name: '', pem: '' }
    await loadAssets()
    api.value = { ...api.value, mtls: { ...api.value.mtls, ca_cert_id: res.data.id } }
  } catch (e) {
    uploadError.value = problemText(e)
  } finally {
    uploading.value = false
  }
}

const docOptions = computed(() => [
  { value: '', label: t('api.docs.none') },
  ...docs.value.map((d) => ({ value: d.id, label: `${d.name} (OpenAPI ${d.version})` })),
])
const caOptions = computed(() => [
  { value: '', label: t('api.mtls.none') },
  ...bundles.value.map((b) => ({ value: b.id, label: b.name })),
])
const sourceOptions = computed(() =>
  KEY_SOURCES.map((value) => ({ value, label: t(`api.jwt.sources.${value}`) })),
)
</script>

<template>
  <SkPageHeader
    :title="title"
    :description="t('api.description')"
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
      {{ t('api.readOnly') }}
    </p>

    <form class="flex max-w-3xl flex-col gap-6" novalidate @submit.prevent="save">
      <WriteBanners
        :stale="flow.stale.value"
        :precondition="flow.precondition.value"
        :unmatched="form.unmatched.value"
        @reload="load"
      />

      <section class="flex flex-col gap-4" aria-labelledby="api-general">
        <h2 id="api-general" class="text-lg font-semibold">{{ t('api.sections.general') }}</h2>
        <SkFormField :label="t('api.enabled.label')" :error="form.errorFor('enabled')">
          <template #default="{ attrs }">
            <SwitchControl
              v-bind="attrs"
              :model-value="api.enabled === true"
              :label="t('api.enabled.switch')"
              :disabled="!canWrite"
              @update:model-value="set('enabled', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('api.docs.label')"
          :help="t('api.docs.help')"
          :error="form.errorFor('openapi_doc_id')"
        >
          <template #default="{ attrs, invalid }">
            <SelectControl
              v-bind="attrs"
              :model-value="api.openapi_doc_id ?? ''"
              :options="docOptions"
              :disabled="!canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="set('openapi_doc_id', $event || undefined)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('api.unknownPath.label')"
          :help="t('api.unknownPath.help')"
          :error="form.errorFor('unknown_path_action')"
        >
          <template #default="{ attrs }">
            <SelectControl
              v-bind="attrs"
              :model-value="api.unknown_path_action ?? 'log'"
              :options="pick(ACTIONS, 'api.actions')"
              :disabled="!canWrite"
              @update:model-value="set('unknown_path_action', $event)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('api.schemaViolation.label')"
          :help="t('api.schemaViolation.help')"
          :error="form.errorFor('schema_violation_action')"
        >
          <template #default="{ attrs }">
            <SelectControl
              v-bind="attrs"
              :model-value="api.schema_violation_action ?? 'log'"
              :options="pick(ACTIONS, 'api.actions')"
              :disabled="!canWrite"
              @update:model-value="set('schema_violation_action', $event)"
            />
          </template>
        </SkFormField>
      </section>

      <section class="flex flex-col gap-4" aria-labelledby="api-jwt">
        <h2 id="api-jwt" class="text-lg font-semibold">{{ t('api.sections.jwt') }}</h2>
        <p class="text-sk-muted">{{ t('api.jwt.help') }}</p>
        <p v-if="form.errorFor('jwt')" role="alert" class="text-sk-danger">
          {{ form.errorFor('jwt') }}
        </p>
        <p v-if="!rules.length" class="text-sk-muted">{{ t('api.jwt.empty') }}</p>
        <fieldset
          v-for="(rule, i) in rules"
          :key="i"
          class="flex flex-col gap-3 rounded-sk border border-sk-border p-4"
          :data-testid="`jwt-rule-${i}`"
        >
          <legend class="px-1 font-medium">{{ t('api.jwt.legend', { n: i + 1 }) }}</legend>
          <SkFormField
            :label="t('api.jwt.paths.label')"
            :help="t('api.jwt.paths.help')"
            :error="form.errorFor(`jwt.${i}.match.paths`)"
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
          <SkFormField :label="t('api.jwt.methods.label')" :help="t('api.jwt.methods.help')">
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
          <SkFormField :label="t('api.jwt.source.label')">
            <template #default="{ attrs }">
              <SelectControl
                v-bind="attrs"
                :model-value="rule.source"
                :options="sourceOptions"
                :disabled="!canWrite"
                @update:model-value="patchRule(i, { source: $event ?? 'jwks_url', key: '' })"
              />
            </template>
          </SkFormField>
          <SkFormField
            :label="t(`api.jwt.sources.${rule.source}`)"
            :help="t(`api.jwt.sourceHelp.${rule.source}`)"
            :error="form.errorFor(`jwt.${i}`) || form.errorFor(`jwt.${i}.${rule.source}`)"
          >
            <template #default="{ attrs }">
              <textarea
                v-if="rule.source === 'public_key_pem'"
                v-bind="attrs"
                :class="[controlClass, 'font-mono']"
                rows="5"
                :value="rule.key"
                :disabled="!canWrite"
                spellcheck="false"
                @input="patchRule(i, { key: ($event.target as HTMLTextAreaElement).value })"
              />
              <TextControl
                v-else
                v-bind="attrs"
                mono
                :model-value="rule.key"
                :disabled="!canWrite"
                @update:model-value="patchRule(i, { key: $event })"
              />
            </template>
          </SkFormField>
          <SkFormField :label="t('api.jwt.issuer.label')" :error="form.errorFor(`jwt.${i}.issuer`)">
            <template #default="{ attrs }">
              <TextControl
                v-bind="attrs"
                mono
                :model-value="rule.issuer"
                :disabled="!canWrite"
                @update:model-value="patchRule(i, { issuer: $event })"
              />
            </template>
          </SkFormField>
          <SkFormField
            :label="t('api.jwt.audiences.label')"
            :help="t('api.jwt.audiences.help')"
            :error="form.errorFor(`jwt.${i}.audiences`)"
          >
            <template #default="{ attrs }">
              <TextControl
                v-bind="attrs"
                mono
                :model-value="rule.audiences"
                :disabled="!canWrite"
                @update:model-value="patchRule(i, { audiences: $event })"
              />
            </template>
          </SkFormField>
          <SkFormField
            :label="t('api.jwt.clockSkew.label')"
            :help="t('api.jwt.clockSkew.help')"
            :error="form.errorFor(`jwt.${i}.clock_skew`)"
          >
            <template #default="{ attrs }">
              <TextControl
                v-bind="attrs"
                mono
                :model-value="rule.clockSkew"
                :disabled="!canWrite"
                @update:model-value="patchRule(i, { clockSkew: $event })"
              />
            </template>
          </SkFormField>
          <SwitchControl
            :model-value="rule.optional"
            :label="t('api.jwt.optional')"
            :disabled="!canWrite"
            @update:model-value="patchRule(i, { optional: $event })"
          />
          <SkFormField :label="t('api.jwt.action.label')" :help="t('api.jwt.action.help')">
            <template #default="{ attrs }">
              <SelectControl
                v-bind="attrs"
                :model-value="rule.action"
                :options="[
                  { value: 'block', label: t('api.actions.block') },
                  { value: 'log', label: t('api.actions.log') },
                ]"
                :disabled="!canWrite"
                @update:model-value="patchRule(i, { action: $event === 'log' ? 'log' : 'block' })"
              />
            </template>
          </SkFormField>
          <div v-if="canWrite">
            <Button
              type="button"
              severity="secondary"
              icon="ti ti-trash"
              :label="t('common.actions.delete')"
              :aria-label="t('api.jwt.remove', { n: i + 1 })"
              @click="removeRule(i)"
            />
          </div>
        </fieldset>
        <div v-if="canWrite">
          <Button
            type="button"
            severity="secondary"
            icon="ti ti-plus"
            :label="t('api.jwt.add')"
            @click="addRule"
          />
        </div>
      </section>

      <section class="flex flex-col gap-4" aria-labelledby="api-mtls">
        <h2 id="api-mtls" class="text-lg font-semibold">{{ t('api.sections.mtls') }}</h2>
        <p class="text-sk-muted">{{ t('api.mtls.help') }}</p>
        <SkFormField :label="t('api.mtls.ca.label')" :error="form.errorFor('mtls.ca_cert_id')">
          <template #default="{ attrs }">
            <SelectControl
              v-bind="attrs"
              :model-value="api.mtls?.ca_cert_id ?? ''"
              :options="caOptions"
              :disabled="!canWrite"
              @update:model-value="
                api = { ...api, mtls: { ...api.mtls, ca_cert_id: $event || undefined } }
              "
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('api.mtls.paths.label')"
          :help="t('api.mtls.paths.help')"
          :error="form.errorFor('mtls.required_paths')"
        >
          <template #default="{ attrs }">
            <TextControl v-bind="attrs" v-model="requiredPaths" mono :disabled="!canWrite" />
          </template>
        </SkFormField>
      </section>

      <div v-if="canWrite">
        <Button type="submit" :label="t('common.actions.save')" :loading="busy" :disabled="busy" />
      </div>
    </form>

    <section
      v-if="canWrite"
      class="mt-8 flex max-w-3xl flex-col gap-4"
      aria-labelledby="api-uploads"
    >
      <h2 id="api-uploads" class="text-lg font-semibold">{{ t('api.sections.uploads') }}</h2>
      <p v-if="uploadError" role="alert" class="text-sk-danger">{{ uploadError }}</p>
      <form
        class="flex flex-col gap-3 rounded-sk border border-sk-border p-4"
        @submit.prevent="uploadDoc"
      >
        <h3 class="font-medium">{{ t('api.docs.uploadTitle') }}</h3>
        <SkFormField :label="t('api.docs.id')" :help="t('api.docs.idHelp')" required>
          <template #default="{ attrs }">
            <TextControl v-bind="attrs" v-model="docDraft.id" mono />
          </template>
        </SkFormField>
        <SkFormField :label="t('api.docs.name')">
          <template #default="{ attrs }">
            <TextControl v-bind="attrs" v-model="docDraft.name" />
          </template>
        </SkFormField>
        <SkFormField :label="t('api.docs.file')" :help="t('api.docs.fileHelp')">
          <template #default="{ attrs }">
            <input
              v-bind="attrs"
              type="file"
              accept=".json,.yaml,.yml,application/json"
              @change="
                readFile($event, (text, name) => {
                  docDraft.content = text
                  if (!docDraft.id)
                    docDraft.id = name
                      .replace(/\.[^.]+$/, '')
                      .toLowerCase()
                      .replace(/[^a-z0-9-]+/g, '-')
                      .slice(0, 63)
                })
              "
            />
          </template>
        </SkFormField>
        <div>
          <Button
            type="submit"
            :label="t('api.docs.upload')"
            :loading="uploading"
            :disabled="uploading || !docDraft.id || !docDraft.content"
          />
        </div>
      </form>
      <form
        class="flex flex-col gap-3 rounded-sk border border-sk-border p-4"
        @submit.prevent="uploadCA"
      >
        <h3 class="font-medium">{{ t('api.mtls.uploadTitle') }}</h3>
        <SkFormField :label="t('api.docs.name')" required>
          <template #default="{ attrs }">
            <TextControl v-bind="attrs" v-model="caDraft.name" />
          </template>
        </SkFormField>
        <SkFormField :label="t('api.mtls.pem')" :help="t('api.mtls.pemHelp')" required>
          <template #default="{ attrs }">
            <textarea
              v-bind="attrs"
              v-model="caDraft.pem"
              :class="[controlClass, 'font-mono']"
              rows="5"
              spellcheck="false"
            />
          </template>
        </SkFormField>
        <div>
          <Button
            type="submit"
            :label="t('api.mtls.upload')"
            :loading="uploading"
            :disabled="uploading || !caDraft.name || !caDraft.pem"
          />
        </div>
      </form>
    </section>

    <section class="mt-8 max-w-3xl" aria-labelledby="api-endpoints">
      <h2 id="api-endpoints" class="mb-2 text-lg font-semibold">
        {{ t('api.sections.endpoints') }}
      </h2>
      <p v-if="!api.openapi_doc_id" class="text-sk-muted">{{ t('api.endpoints.noDoc') }}</p>
      <p v-else-if="endpointsError" role="alert" class="text-sk-danger">
        {{ t('api.endpoints.loadFailed') }}
      </p>
      <template v-else-if="endpoints">
        <p class="mb-2 text-sk-muted">{{ t('api.endpoints.help') }}</p>
        <div class="overflow-x-auto">
          <table class="w-full text-left" data-testid="api-endpoints">
            <caption class="sr-only">
              {{
                t('api.endpoints.caption')
              }}
            </caption>
            <thead>
              <tr class="border-b border-sk-border">
                <th scope="col" class="py-2 pr-4">{{ t('api.endpoints.method') }}</th>
                <th scope="col" class="py-2 pr-4">{{ t('api.endpoints.path') }}</th>
                <th scope="col" class="py-2 text-right">{{ t('api.endpoints.violations') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="e in endpoints.items"
                :key="e.method + e.path"
                class="border-b border-sk-border"
              >
                <td class="py-2 pr-4 font-mono">{{ e.method }}</td>
                <td class="py-2 pr-4 font-mono">{{ e.path }}</td>
                <td class="py-2 text-right tabular-nums">{{ e.schema_violations }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <template v-if="endpoints.undocumented.length">
          <h3 class="mb-2 mt-6 font-medium">{{ t('api.endpoints.undocumented') }}</h3>
          <ul class="font-mono" data-testid="api-undocumented">
            <li v-for="u in endpoints.undocumented" :key="u.method + u.path">
              {{ u.method }} {{ u.path }} — {{ u.count }}
            </li>
          </ul>
        </template>
      </template>
    </section>
  </template>
</template>
