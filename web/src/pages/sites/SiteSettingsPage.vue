<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SkStatusBadge from '@/components/SkStatusBadge.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import BlockConfirmDialog from './BlockConfirmDialog.vue'
import { clone, mergePatch } from './lib/json'
import {
  hydrate,
  siteFieldPaths,
  siteListFields,
  toSite,
  type Site,
  type SiteDraft,
} from './lib/siteDraft'
import { useLookups } from './lib/useLookups'
import { useSiteContext } from './lib/useSiteContext'
import { useWriteFlow } from './lib/useWriteFlow'
import SelectControl from './controls/SelectControl.vue'
import SiteFormFields from './SiteFormFields.vue'
import SiteTabs from './SiteTabs.vue'
import WriteBanners from './WriteBanners.vue'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()
const siteId = computed(() => String(route.params.site))
const ctx = useSiteContext(() => siteId.value)
const lookups = useLookups()

const draft = ref<SiteDraft>()
// The last server version, in wire form, that the patch is computed against.
const baseline = ref<Site>()
const busy = ref(false)
const confirmBlock = ref<'form' | 'switcher' | false>(false)
const pendingMode = ref<'off' | 'detect' | 'block'>('detect')
const confirmDelete = ref(false)

const canWrite = computed(() => session.can('config:write'))
const form = useFormErrors({ known: siteFieldPaths })
const flow = useWriteFlow({
  form,
  rebase: () => ({ prefixes: [`/sites/${ctx.index.value}`], lists: siteListFields }),
})

const currentMode = computed(() => baseline.value?.policy?.mode ?? ctx.defaults.value.mode ?? 'off')
const displayName = computed(() => draft.value?.name || siteId.value)

async function load() {
  flow.reset()
  await Promise.all([ctx.load(), lookups.load()])
  if (ctx.site.value) {
    draft.value = hydrate(ctx.site.value)
    baseline.value = toSite(hydrate(ctx.site.value))
  }
}
onMounted(load)

function patchBody() {
  return draft.value ? mergePatch(baseline.value, toSite(draft.value)) : undefined
}

function submit() {
  flow.reset()
  const becomesBlock =
    draft.value?.policy.mode === 'block' && baseline.value?.policy?.mode !== 'block'
  if (becomesBlock) confirmBlock.value = 'form'
  else void save()
}

async function patch(body: Record<string, unknown>): Promise<boolean> {
  if (!ctx.etag.value) {
    flow.precondition.value = true
    return false
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
    // The response is the new config version; its id is the next If-Match.
    ctx.etag.value = res.etag ?? ctx.etag.value
    return true
  } catch (e) {
    flow.handle(e)
    return false
  } finally {
    busy.value = false
  }
}

async function save() {
  confirmBlock.value = false
  const body = patchBody()
  if (!body || !draft.value) {
    toasts.info(t('sites.noChanges'))
    return
  }
  if (await patch(body)) {
    baseline.value = toSite(clone(draft.value))
    toasts.success(t('sites.saved'))
  }
}

function chooseMode(mode: 'off' | 'detect' | 'block' | undefined) {
  if (!mode || mode === currentMode.value) return
  flow.reset()
  pendingMode.value = mode
  if (mode === 'block') confirmBlock.value = 'switcher'
  else void applyMode(mode)
}

async function applyMode(mode: 'off' | 'detect' | 'block') {
  confirmBlock.value = false
  if (await patch({ policy: { mode } })) {
    // Keep any unsaved edits in the form; only the mode moved on the server.
    if (baseline.value) {
      baseline.value = { ...baseline.value, policy: { ...baseline.value.policy, mode } }
    }
    if (draft.value) draft.value = { ...draft.value, policy: { ...draft.value.policy, mode } }
    toasts.success(t('sites.modeChanged', { mode: t(`common.status.mode.${mode}`) }))
  }
}

function confirmedBlock() {
  if (confirmBlock.value === 'switcher') void applyMode('block')
  else void save()
}

async function remove() {
  if (!ctx.etag.value) return
  busy.value = true
  try {
    await call(
      client.DELETE('/sites/{site}', {
        params: { path: { site: siteId.value }, header: ifMatch(ctx.etag.value) },
      }),
      { toast: false },
    )
    confirmDelete.value = false
    toasts.success(t('sites.deleted', { site: siteId.value }))
    await router.push({ name: 'sites' })
  } catch (e) {
    confirmDelete.value = false
    flow.handle(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader
    :title="displayName"
    :description="t('sites.settingsDescription')"
    :breadcrumbs="[{ label: t('sites.title'), to: '/sites' }, { label: displayName }]"
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
    v-else-if="ctx.state.value === 'error' || !draft"
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

    <section
      class="mb-6 flex flex-wrap items-end gap-4"
      :aria-label="t('sites.modeSwitcher.label')"
    >
      <div>
        <p class="text-sm font-medium">{{ t('sites.modeSwitcher.current') }}</p>
        <SkStatusBadge :mode="currentMode" />
      </div>
      <div v-if="canWrite" class="flex flex-col gap-1">
        <label for="mode-switcher" class="text-sm font-medium">
          {{ t('sites.modeSwitcher.change') }}
        </label>
        <SelectControl
          id="mode-switcher"
          :model-value="currentMode"
          :options="
            (['off', 'detect', 'block'] as const).map((m) => ({
              value: m,
              label: t(`common.status.mode.${m}`),
            }))
          "
          :disabled="busy"
          @update:model-value="chooseMode"
        />
      </div>
    </section>

    <form class="flex flex-col gap-6" novalidate @submit.prevent="submit">
      <WriteBanners
        :stale="flow.stale.value"
        :precondition="flow.precondition.value"
        :unmatched="form.unmatched.value"
        @reload="load"
      />
      <SiteFormFields
        v-model="draft"
        :is-new="false"
        :readonly="!canWrite"
        :certificates="lookups.certificates.value"
        :block-pages="lookups.blockPages.value"
        :defaults="ctx.defaults.value"
        :error-for="form.errorFor"
        :clear-error="form.clear"
      />
      <div v-if="canWrite">
        <Button type="submit" :label="t('common.actions.save')" :loading="busy" :disabled="busy" />
      </div>
    </form>

    <section v-if="canWrite" class="mt-10 border-t border-sk-border pt-6">
      <h2 class="text-lg font-semibold text-sk-danger">{{ t('sites.danger.title') }}</h2>
      <p class="mb-3 text-sk-muted">{{ t('sites.danger.description') }}</p>
      <Button
        :label="t('sites.danger.delete')"
        severity="danger"
        icon="ti ti-trash"
        @click="confirmDelete = true"
      />
    </section>
  </template>

  <BlockConfirmDialog
    v-if="canWrite"
    :open="confirmBlock !== false"
    :site-name="displayName"
    :busy="busy"
    @update:open="confirmBlock = false"
    @confirm="confirmedBlock"
  />
  <SkConfirmDialog
    v-if="canWrite"
    v-model:open="confirmDelete"
    danger
    :busy="busy"
    :title="t('sites.danger.dialogTitle', { site: siteId })"
    :message="t('sites.danger.dialogMessage')"
    :confirm-text="siteId"
    :confirm-label="t('sites.danger.delete')"
    @confirm="remove"
  />
</template>
