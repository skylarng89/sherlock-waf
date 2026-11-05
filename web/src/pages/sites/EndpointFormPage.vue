<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import SelectControl from './controls/SelectControl.vue'
import TextControl from './controls/TextControl.vue'
import AccessSections from '@/pages/access/AccessSections.vue'
import { accessPolicyLists, accessPolicyPaths, pruneAccessPolicy } from '@/pages/access/policy'
import { useIpListNames } from '@/pages/access/useIpListNames'
import { clone, mergePatch } from './lib/json'
import type { Policy, PolicyLayer } from './lib/layers'
import { matchKindOf, matchValueOf, type Endpoint, type MatchKind } from './lib/precedence'
import { SITE_ID_PATTERN } from './lib/siteDraft'
import { useLookups } from './lib/useLookups'
import { useSiteContext } from './lib/useSiteContext'
import { useWriteFlow } from './lib/useWriteFlow'
import { policyFields, policyListFields } from './policyFields'
import PolicyForm from './PolicyForm.vue'
import WriteBanners from './WriteBanners.vue'

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()
const siteId = computed(() => String(route.params.site))
const endpointId = computed(() =>
  route.params.endpoint === undefined ? undefined : String(route.params.endpoint),
)
const isNew = computed(() => endpointId.value === undefined)
const ctx = useSiteContext(() => siteId.value)
const lookups = useLookups()
const ipLists = useIpListNames()
const canWrite = computed(() => session.can('config:write'))

const id = ref('')
const kind = ref<MatchKind>('path_prefix')
const value = ref('')
const methods = ref<string[]>([])
const policy = ref<Policy>({})
const baseline = ref<Endpoint>()
const busy = ref(false)
const missingEndpoint = ref(false)

const form = useFormErrors({
  known: [
    'id',
    'match',
    'match.methods',
    ...policyFields.map((f) => `policy.${f.path}`),
    ...accessPolicyPaths('policy.'),
  ],
  // The match form has one path input whichever of path / path_prefix / path_glob is chosen.
  aliases: {
    'match.path': 'match',
    'match.path_prefix': 'match',
    'match.path_glob': 'match',
  },
})
const endpointIndex = computed(() => {
  const list = ctx.site.value?.endpoints ?? []
  return isNew.value ? list.length : list.findIndex((e) => e.id === endpointId.value)
})
const flow = useWriteFlow({
  form,
  rebase: () => ({
    prefixes: [
      `/sites/${ctx.index.value}/endpoints/${endpointIndex.value}`,
      `/sites/${ctx.index.value}`,
    ],
    lists: [
      'match.methods',
      ...policyListFields.map((p) => `policy.${p}`),
      ...accessPolicyLists('policy.'),
    ],
  }),
  onConflict: () => {
    form.errors.value = { ...form.errors.value, id: t('sites.endpoints.errors.duplicate') }
  },
})

/** Inherited values come from the site, then the global defaults (this endpoint is not a layer). */
const layers = computed<PolicyLayer[]>(() => [
  { label: t('sites.source.site'), policy: ctx.site.value?.policy },
  { label: t('sites.source.global'), policy: ctx.defaults.value },
])

const title = computed(() =>
  isNew.value ? t('sites.endpoints.newTitle') : (endpointId.value ?? ''),
)
const siteTitle = computed(() => ctx.site.value?.name || siteId.value)

function wire(): Endpoint {
  const match: Endpoint['match'] = { [kind.value]: value.value }
  if (methods.value.length) match.methods = [...methods.value]
  return { id: id.value, match, policy: pruneAccessPolicy(clone(policy.value)) }
}

async function load() {
  flow.reset()
  missingEndpoint.value = false
  await Promise.all([ctx.load(), lookups.load(), ipLists.load()])
  if (!isNew.value) {
    const found = ctx.site.value?.endpoints?.find((e) => e.id === endpointId.value)
    if (!found) {
      missingEndpoint.value = true
      return
    }
    id.value = found.id
    kind.value = matchKindOf(found.match)
    value.value = matchValueOf(found.match)
    methods.value = [...(found.match.methods ?? [])]
    policy.value = clone(found.policy ?? {})
    baseline.value = wire()
  }
}
onMounted(load)

function submit() {
  flow.reset()
  const errors: Record<string, string> = {}
  if (isNew.value && !SITE_ID_PATTERN.test(id.value)) errors.id = t('sites.errors.idPattern')
  if (!value.value.trim()) errors.match = t('sites.endpoints.errors.matchRequired')
  form.errors.value = errors
  if (Object.keys(errors).length === 0) void save()
}

async function save() {
  if (!ctx.etag.value) {
    flow.precondition.value = true
    return
  }
  busy.value = true
  const body = wire()
  try {
    if (isNew.value) {
      await call(
        client.POST('/sites/{site}/endpoints', {
          params: { path: { site: siteId.value }, header: ifMatch(ctx.etag.value) },
          body,
        }),
        { toast: false },
      )
    } else {
      const patch = mergePatch(baseline.value, body)
      if (!patch) {
        toasts.info(t('sites.noChanges'))
        return
      }
      await call(
        client.PATCH('/sites/{site}/endpoints/{endpoint}', {
          params: {
            path: { site: siteId.value, endpoint: body.id },
            header: ifMatch(ctx.etag.value),
          },
          headers: { 'Content-Type': 'application/merge-patch+json' },
          body: patch,
        }),
        { toast: false },
      )
    }
    toasts.success(t('sites.endpoints.saved', { id: body.id }))
    await router.push({ name: 'site-endpoints', params: { site: siteId.value } })
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
    :description="t('sites.endpoints.formDescription')"
    :breadcrumbs="[
      { label: t('sites.title'), to: '/sites' },
      { label: siteTitle, to: `/sites/${siteId}/endpoints` },
      { label: title },
    ]"
  />

  <p v-if="ctx.state.value === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="ctx.state.value !== 'ready' || missingEndpoint"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    {{ ctx.state.value === 'error' ? t('sites.loadFailed') : t('sites.endpoints.notFound') }}
    <RouterLink :to="`/sites/${siteId}/endpoints`" class="underline">
      {{ t('sites.endpoints.backToList') }}
    </RouterLink>
  </div>
  <template v-else>
    <p v-if="!canWrite" role="status" class="mb-4 text-sk-muted">
      <i class="ti ti-lock" aria-hidden="true" />
      {{ t('sites.readOnly') }}
    </p>
    <form class="flex flex-col gap-6" novalidate @submit.prevent="submit">
      <WriteBanners
        :stale="flow.stale.value"
        :precondition="flow.precondition.value"
        :unmatched="form.unmatched.value"
        @reload="load"
      />
      <fieldset class="flex flex-col gap-4" :disabled="!canWrite">
        <legend class="mb-2 text-lg font-semibold">{{ t('sites.endpoints.matchSection') }}</legend>
        <SkFormField
          :label="t('sites.endpoints.fields.id')"
          :help="isNew ? t('sites.fields.id.help') : t('sites.endpoints.fields.idImmutable')"
          :error="form.errorFor('id')"
          required
        >
          <template #default="{ attrs, invalid }">
            <TextControl
              v-bind="attrs"
              v-model="id"
              mono
              :disabled="!isNew || !canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="form.clear('id')"
            />
          </template>
        </SkFormField>
        <SkFormField :label="t('sites.endpoints.fields.kind')">
          <template #default="{ attrs }">
            <SelectControl
              v-bind="attrs"
              v-model="kind"
              :options="
                (['path', 'path_prefix', 'path_glob'] as const).map((k) => ({
                  value: k,
                  label: t(`sites.endpoints.kind.${k}`),
                }))
              "
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('sites.endpoints.fields.value')"
          :help="t(`sites.endpoints.kindHelp.${kind}`)"
          :error="form.errorFor('match')"
          required
        >
          <template #default="{ attrs, invalid }">
            <TextControl
              v-bind="attrs"
              v-model="value"
              mono
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="form.clear('match')"
            />
          </template>
        </SkFormField>
        <div
          role="group"
          aria-labelledby="methods-legend"
          :aria-describedby="form.errorFor('match.methods') ? 'methods-error' : undefined"
        >
          <p id="methods-legend" class="text-sm font-medium">
            {{ t('sites.endpoints.fields.methods') }}
          </p>
          <p class="text-sm text-sk-muted">{{ t('sites.endpoints.fields.methodsHelp') }}</p>
          <div class="mt-1 flex flex-wrap gap-4">
            <label v-for="m in METHODS" :key="m" class="flex items-center gap-2">
              <input
                v-model="methods"
                type="checkbox"
                :value="m"
                class="size-4 accent-[var(--sk-accent)]"
              />
              {{ m }}
            </label>
          </div>
          <p id="methods-error" aria-live="polite" class="text-sm text-sk-danger">
            {{ form.errorFor('match.methods') }}
          </p>
        </div>
      </fieldset>

      <fieldset class="flex flex-col gap-4">
        <legend class="mb-2 text-lg font-semibold">{{ t('sites.endpoints.policySection') }}</legend>
        <p class="text-sk-muted">{{ t('sites.endpoints.policyHelp') }}</p>
        <PolicyForm
          v-model="policy"
          :layers="layers"
          :block-pages="lookups.blockPages.value"
          :disabled="!canWrite"
          :error-for="(p) => form.errorFor(`policy.${p}`)"
        />
        <AccessSections
          v-model="policy"
          scope="endpoint"
          :layers="layers"
          :known="ipLists.names.value"
          :disabled="!canWrite"
          :error-for="(p) => form.errorFor(`policy.${p}`)"
        />
      </fieldset>

      <div v-if="canWrite" class="flex gap-2">
        <Button
          type="submit"
          :label="isNew ? t('sites.endpoints.create') : t('common.actions.save')"
          :loading="busy"
          :disabled="busy"
        />
        <Button
          type="button"
          severity="secondary"
          :label="t('common.actions.cancel')"
          @click="router.push({ name: 'site-endpoints', params: { site: siteId } })"
        />
      </div>
    </form>
  </template>
</template>
