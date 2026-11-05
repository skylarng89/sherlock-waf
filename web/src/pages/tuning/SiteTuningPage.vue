<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { useApi } from '@/api/useApi'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { useSiteContext } from '@/pages/sites/lib/useSiteContext'
import { useWriteFlow } from '@/pages/sites/lib/useWriteFlow'
import SiteTabs from '@/pages/sites/SiteTabs.vue'
import WriteBanners from '@/pages/sites/WriteBanners.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import ExclusionsPanel from './ExclusionsPanel.vue'
import { effectiveLevels } from './lib'
import OutboundPanel from './OutboundPanel.vue'
import ParanoiaHelper from './ParanoiaHelper.vue'

const { t } = useI18n()
const route = useRoute()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()
const siteId = computed(() => String(route.params.site))
const ctx = useSiteContext(() => siteId.value)
const canWrite = computed(() => session.can('config:write'))
const form = useFormErrors()
const flow = useWriteFlow({ form, rebase: () => ({ prefixes: [`/sites/${ctx.index.value}`] }) })
const busy = ref(false)
const exclusions = ref<InstanceType<typeof ExclusionsPanel>>()

const title = computed(() => ctx.site.value?.name || siteId.value)
const levels = computed(() => effectiveLevels(ctx.site.value?.policy, ctx.defaults.value))

async function load() {
  flow.reset()
  await ctx.load()
  await exclusions.value?.load()
}
onMounted(() => ctx.load())

/** Re-reads the site list without flipping the page to its loading state. */
async function refresh() {
  const list = await call(client.GET('/sites'), { toast: false })
  ctx.sites.value = list.data.items
  ctx.etag.value = list.etag ?? ctx.etag.value
  ctx.site.value = list.data.items.find((s) => s.id === siteId.value)
}

/** Merge-patches policy.waf on the site; null removes a field. */
async function saveWaf(waf: Record<string, unknown>): Promise<boolean> {
  if (!ctx.etag.value) {
    flow.precondition.value = true
    return false
  }
  busy.value = true
  flow.reset()
  try {
    const res = await call(
      client.PATCH('/sites/{site}', {
        params: { path: { site: siteId.value }, header: ifMatch(ctx.etag.value) },
        headers: { 'Content-Type': 'application/merge-patch+json' },
        body: { policy: { waf } },
      }),
      { toast: false },
    )
    ctx.etag.value = res.etag ?? ctx.etag.value
    await refresh()
    toasts.success(t('tuning.tuning.saved'))
    return true
  } catch (e) {
    flow.handle(e)
    return false
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader
    :title="title"
    :description="t('tuning.tuning.description')"
    :breadcrumbs="[{ label: t('sites.title'), to: '/sites' }, { label: title }]"
  />

  <p v-if="ctx.state.value === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="ctx.state.value === 'missing' || ctx.state.value === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    {{ ctx.state.value === 'missing' ? t('sites.notFound') : t('tuning.tuning.loadFailed') }}
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
    <div class="flex flex-col gap-6">
      <ExclusionsPanel
        ref="exclusions"
        :site="siteId"
        :can-write="canWrite"
        @stale="flow.stale.value = true"
      />
      <ParanoiaHelper
        :site="siteId"
        :detect="levels.detect"
        :block="levels.block"
        :can-write="canWrite"
        :busy="busy"
        :save="saveWaf"
      />
      <OutboundPanel
        :waf="ctx.site.value?.policy?.waf"
        :can-write="canWrite"
        :busy="busy"
        :save="saveWaf"
      />
    </div>
  </template>
</template>
