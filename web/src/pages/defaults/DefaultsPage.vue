<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormErrors } from '@/api/fieldErrors'
import { ApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import { extensionSettingsPanels } from '@/extensions'
import AccessSections from '@/pages/access/AccessSections.vue'
import { accessPolicyLists, accessPolicyPaths, pruneAccessPolicy } from '@/pages/access/policy'
import { useIpListNames } from '@/pages/access/useIpListNames'
import { clone } from '@/pages/sites/lib/json'
import type { Policy } from '@/pages/sites/lib/layers'
import { useLookups } from '@/pages/sites/lib/useLookups'
import { useWriteFlow } from '@/pages/sites/lib/useWriteFlow'
import { policyFields, policyListFields } from '@/pages/sites/policyFields'
import PolicyForm from '@/pages/sites/PolicyForm.vue'
import WriteBanners from '@/pages/sites/WriteBanners.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'

const { t, te } = useI18n()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()
const lookups = useLookups()
const ipLists = useIpListNames()

const state = ref<'loading' | 'ready' | 'error'>('loading')
const policy = ref<Policy>({})
const etag = ref<string>()
const busy = ref(false)
const canWrite = computed(() => session.can('config:write'))

const form = useFormErrors({
  known: [...policyFields.map((f) => f.path), ...accessPolicyPaths()],
})
const flow = useWriteFlow({
  form,
  // The server addresses the defaults inside the whole document: /global/defaults/...
  rebase: () => ({
    prefixes: ['/global/defaults'],
    lists: [...policyListFields, ...accessPolicyLists()],
  }),
})

const panels = computed(() =>
  [...extensionSettingsPanels.value]
    .filter((p) => session.can(p.permission))
    .sort((a, b) => (a.order ?? 100) - (b.order ?? 100)),
)

async function load() {
  flow.reset()
  state.value = 'loading'
  try {
    const [res] = await Promise.all([
      call(client.GET('/defaults'), { toast: false }).catch((e: unknown) => {
        // Nothing stored yet: start from an empty policy (built-in defaults apply).
        if (e instanceof ApiError && e.kind === 'not_found') return { data: {}, etag: undefined }
        throw e
      }),
      lookups.load(),
      ipLists.load(),
    ])
    policy.value = clone(res.data as Policy)
    etag.value = res.etag
    state.value = 'ready'
  } catch {
    state.value = 'error'
  }
}
onMounted(load)

async function save() {
  flow.reset()
  if (!etag.value) {
    flow.precondition.value = true
    return
  }
  busy.value = true
  try {
    const res = await call(
      client.PUT('/defaults', {
        params: { header: ifMatch(etag.value) },
        body: pruneAccessPolicy(clone(policy.value)) ?? {},
      }),
      { toast: false },
    )
    etag.value = res.etag ?? etag.value
    toasts.success(t('defaults.saved'))
  } catch (e) {
    flow.handle(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader :title="t('defaults.title')" :description="t('defaults.description')" />

  <p v-if="state === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="state === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    <p>
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ t('defaults.loadFailed') }}
    </p>
    <Button :label="t('common.actions.retry')" severity="secondary" @click="load" />
  </div>
  <template v-else>
    <p v-if="!canWrite" role="status" class="mb-4 text-sk-muted">
      <i class="ti ti-lock" aria-hidden="true" />
      {{ t('defaults.readOnly') }}
    </p>
    <p class="mb-4 text-sk-muted">{{ t('defaults.inheritanceNote') }}</p>
    <form class="flex flex-col gap-6" novalidate @submit.prevent="save">
      <WriteBanners
        :stale="flow.stale.value"
        :precondition="flow.precondition.value"
        :unmatched="form.unmatched.value"
        @reload="load"
      />
      <PolicyForm
        v-model="policy"
        :block-pages="lookups.blockPages.value"
        :disabled="!canWrite"
        :error-for="form.errorFor"
      />
      <AccessSections
        v-model="policy"
        scope="defaults"
        :known="ipLists.names.value"
        :disabled="!canWrite"
        :error-for="form.errorFor"
      />
      <div v-if="canWrite">
        <Button type="submit" :label="t('common.actions.save')" :loading="busy" :disabled="busy" />
      </div>
    </form>

    <section
      v-for="panel in panels"
      :key="panel.id"
      class="mt-10 border-t border-sk-border pt-6"
      :aria-labelledby="`panel-${panel.id}`"
    >
      <h2 :id="`panel-${panel.id}`" class="mb-3 text-lg font-semibold">
        {{ te(panel.label) ? t(panel.label) : panel.label }}
      </h2>
      <component :is="panel.component" />
    </section>
  </template>
</template>
