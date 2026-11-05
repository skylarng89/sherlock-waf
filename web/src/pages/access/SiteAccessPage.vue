<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { useApi } from '@/api/useApi'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { clone, mergePatch } from '@/pages/sites/lib/json'
import type { Policy, PolicyLayer } from '@/pages/sites/lib/layers'
import { useSiteContext } from '@/pages/sites/lib/useSiteContext'
import { useWriteFlow } from '@/pages/sites/lib/useWriteFlow'
import SiteTabs from '@/pages/sites/SiteTabs.vue'
import WriteBanners from '@/pages/sites/WriteBanners.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import AclForm from './AclForm.vue'
import AutoBanForm from './AutoBanForm.vue'
import EffectiveAccess from './EffectiveAccess.vue'
import { accessPolicyLists, accessPolicyPaths, pruneAccessPolicy } from './policy'
import RateLimitsForm from './RateLimitsForm.vue'
import { useIpListNames } from './useIpListNames'

/** The ACL tab and the rate-limits tab of a site: the same page, one slice of the policy each. */
const props = defineProps<{ section: 'acl' | 'rate-limits' }>()

const { t } = useI18n()
const route = useRoute()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()
const siteId = computed(() => String(route.params.site))
const ctx = useSiteContext(() => siteId.value)
const lists = useIpListNames()
const canWrite = computed(() => session.can('config:write'))

const policy = ref<Policy>({})
// The last server version of the policy in wire form; the patch is computed against it.
const baseline = ref<Policy>()
const busy = ref(false)

const form = useFormErrors({ known: accessPolicyPaths() })
const flow = useWriteFlow({
  form,
  // The server addresses the site's policy inside the whole document: /sites/<n>/policy/...
  rebase: () => ({ prefixes: [`/sites/${ctx.index.value}/policy`], lists: accessPolicyLists() }),
})

const layers = computed<PolicyLayer[]>(() => [
  { label: t('sites.source.global'), policy: ctx.defaults.value },
])
const title = computed(() => ctx.site.value?.name || siteId.value)

async function load() {
  flow.reset()
  await Promise.all([ctx.load(), lists.load()])
  if (ctx.site.value) {
    policy.value = clone(ctx.site.value.policy ?? {})
    baseline.value = pruneAccessPolicy(policy.value)
  }
}
onMounted(load)

const wrap = (p: Policy | undefined) => (p ? { policy: p } : {})

async function save() {
  flow.reset()
  const next = pruneAccessPolicy(policy.value)
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
    toasts.success(t('access.site.saved'))
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
    :description="
      t(`access.site.${props.section === 'acl' ? 'aclDescription' : 'rateLimitsDescription'}`)
    "
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
      {{ t('sites.readOnly') }}
    </p>
    <form class="flex flex-col gap-6" novalidate @submit.prevent="save">
      <WriteBanners
        :stale="flow.stale.value"
        :precondition="flow.precondition.value"
        :unmatched="form.unmatched.value"
        @reload="load"
      />
      <AclForm
        v-if="section === 'acl'"
        v-model="policy"
        :layers="layers"
        :known="lists.names.value"
        :disabled="!canWrite"
        :error-for="form.errorFor"
      />
      <template v-else>
        <section class="flex flex-col gap-4" :aria-labelledby="'rl-title'">
          <h2 id="rl-title" class="text-lg font-semibold">{{ t('access.sections.rateLimits') }}</h2>
          <RateLimitsForm
            v-model="policy"
            :layers="layers"
            :disabled="!canWrite"
            :error-for="form.errorFor"
          />
        </section>
        <section class="flex flex-col gap-4" :aria-labelledby="'ab-title'">
          <h2 id="ab-title" class="text-lg font-semibold">{{ t('access.sections.autoBan') }}</h2>
          <AutoBanForm
            v-model="policy"
            :layers="layers"
            :disabled="!canWrite"
            :error-for="form.errorFor"
          />
        </section>
      </template>
      <div v-if="canWrite">
        <Button type="submit" :label="t('common.actions.save')" :loading="busy" :disabled="busy" />
      </div>
    </form>

    <div class="mt-10">
      <EffectiveAccess :site="siteId" :section="section" />
    </div>
  </template>
</template>
