<script setup lang="ts">
import Button from 'openvue/button'
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { useApi } from '@/api/useApi'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { useToastStore } from '@/stores/toasts'
import BlockConfirmDialog from './BlockConfirmDialog.vue'
import {
  newSiteDraft,
  SITE_ID_PATTERN,
  siteFieldPaths,
  siteListFields,
  toSite,
} from './lib/siteDraft'
import { useLookups } from './lib/useLookups'
import { useSiteContext } from './lib/useSiteContext'
import { useWriteFlow } from './lib/useWriteFlow'
import SiteFormFields from './SiteFormFields.vue'
import WriteBanners from './WriteBanners.vue'

const { t } = useI18n()
const router = useRouter()
const { client, call, ifMatch } = useApi()
const toasts = useToastStore()
const ctx = useSiteContext(() => undefined)
const lookups = useLookups()

const draft = ref(newSiteDraft())
const busy = ref(false)
const confirmBlock = ref(false)
const form = useFormErrors({ known: siteFieldPaths })
const flow = useWriteFlow({
  form,
  // A new site is appended, so the server addresses it as /sites/<current count>.
  rebase: () => ({ prefixes: [`/sites/${ctx.sites.value.length}`], lists: siteListFields }),
  onConflict: () => {
    form.errors.value = { ...form.errors.value, id: t('sites.errors.duplicate') }
  },
})

onMounted(async () => {
  await Promise.all([ctx.load(), lookups.load()])
})

function validateLocally(): boolean {
  const errors: Record<string, string> = {}
  if (!SITE_ID_PATTERN.test(draft.value.id)) errors.id = t('sites.errors.idPattern')
  if (draft.value.hosts.length === 0) errors.hosts = t('sites.errors.hostsRequired')
  if (draft.value.upstreams.targets.length === 0) {
    errors['upstreams.targets'] = t('sites.errors.targetsRequired')
  }
  form.errors.value = errors
  return Object.keys(errors).length === 0
}

function submit() {
  flow.reset()
  if (!validateLocally()) return
  if (draft.value.policy.mode === 'block') confirmBlock.value = true
  else void save()
}

async function save() {
  confirmBlock.value = false
  busy.value = true
  const site = toSite(draft.value)
  try {
    if (ctx.etag.value) {
      await call(
        client.POST('/sites', { params: { header: ifMatch(ctx.etag.value) }, body: site }),
        { toast: false },
      )
    } else {
      // First configuration on a fresh node: PUT /config needs no If-Match.
      await call(
        client.PUT('/config', {
          params: { header: {} as { 'If-Match': string } },
          body: { schema_version: 1, sites: [site] },
        }),
        { toast: false },
      )
    }
    toasts.success(t('sites.created', { site: site.id }))
    await router.push({ name: 'site-detail', params: { site: site.id } })
  } catch (e) {
    flow.handle(e)
  } finally {
    busy.value = false
  }
}

async function reload() {
  flow.reset()
  await ctx.load()
}
</script>

<template>
  <SkPageHeader
    :title="t('sites.newTitle')"
    :description="t('sites.newDescription')"
    :breadcrumbs="[{ label: t('sites.title'), to: '/sites' }, { label: t('sites.newTitle') }]"
  />

  <p v-if="ctx.state.value === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="ctx.state.value === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    {{ t('sites.loadFailed') }}
    <Button :label="t('common.actions.retry')" severity="secondary" @click="reload" />
  </div>
  <form v-else class="flex flex-col gap-6" novalidate @submit.prevent="submit">
    <WriteBanners
      :stale="flow.stale.value"
      :precondition="flow.precondition.value"
      :unmatched="form.unmatched.value"
      @reload="reload"
    />
    <SiteFormFields
      v-model="draft"
      is-new
      :readonly="false"
      :certificates="lookups.certificates.value"
      :block-pages="lookups.blockPages.value"
      :defaults="ctx.defaults.value"
      :error-for="form.errorFor"
      :clear-error="form.clear"
    />
    <div class="flex gap-2">
      <Button type="submit" :label="t('sites.create')" :loading="busy" :disabled="busy" />
      <Button
        type="button"
        severity="secondary"
        :label="t('common.actions.cancel')"
        @click="router.push({ name: 'sites' })"
      />
    </div>
  </form>

  <BlockConfirmDialog
    v-model:open="confirmBlock"
    :site-name="draft.name || draft.id"
    :busy="busy"
    @confirm="save"
  />
</template>
