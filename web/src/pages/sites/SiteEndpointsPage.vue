<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { flatten } from './lib/layers'
import { matchValueOf, rankEndpoints, type Endpoint } from './lib/precedence'
import { useSiteContext } from './lib/useSiteContext'
import { useWriteFlow } from './lib/useWriteFlow'
import RequestTester from './RequestTester.vue'
import SiteTabs from './SiteTabs.vue'
import WriteBanners from './WriteBanners.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'

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
const ranked = computed(() => rankEndpoints(ctx.site.value?.endpoints ?? []))
const toDelete = ref<Endpoint>()
const busy = ref(false)

const title = computed(() => ctx.site.value?.name || siteId.value)

async function load() {
  flow.reset()
  await ctx.load()
}
onMounted(load)

function matchText(e: Endpoint): string {
  return `${t(`sites.endpoints.kind.${e.match.path ? 'path' : e.match.path_glob ? 'path_glob' : 'path_prefix'}`)}: ${matchValueOf(e.match)}`
}

async function remove() {
  const target = toDelete.value
  if (!target || !ctx.etag.value) return
  busy.value = true
  try {
    await call(
      client.DELETE('/sites/{site}/endpoints/{endpoint}', {
        params: {
          path: { site: siteId.value, endpoint: target.id },
          header: ifMatch(ctx.etag.value),
        },
      }),
      { toast: false },
    )
    toasts.success(t('sites.endpoints.deleted', { id: target.id }))
    toDelete.value = undefined
    await load()
  } catch (e) {
    toDelete.value = undefined
    flow.handle(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader
    :title="title"
    :description="t('sites.endpoints.description')"
    :breadcrumbs="[{ label: t('sites.title'), to: '/sites' }, { label: title }]"
  >
    <template #actions>
      <RouterLink
        v-if="canWrite && ctx.state.value === 'ready'"
        :to="{ name: 'endpoint-new', params: { site: siteId } }"
        class="rounded-sk bg-sk-accent px-4 py-2 font-medium text-sk-accent-contrast hover:bg-sk-accent-hover"
      >
        <i class="ti ti-plus" aria-hidden="true" />
        {{ t('sites.endpoints.add') }}
      </RouterLink>
    </template>
  </SkPageHeader>

  <p v-if="ctx.state.value === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="ctx.state.value === 'missing' || ctx.state.value === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    {{ ctx.state.value === 'missing' ? t('sites.notFound') : t('sites.loadFailed') }}
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

    <SkEmptyState
      v-if="ranked.length === 0"
      :title="t('sites.endpoints.empty.title')"
      :description="t('sites.endpoints.empty.description')"
      icon="ti ti-route"
    />
    <template v-else>
      <p class="mb-3 text-sk-muted" data-testid="precedence-help">
        <i class="ti ti-info-circle" aria-hidden="true" />
        {{ t('sites.endpoints.precedence') }}
      </p>
      <div
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('sites.endpoints.scroll')"
      >
        <table class="w-full text-left">
          <caption class="sr-only">
            {{
              t('sites.endpoints.caption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('sites.endpoints.rank') }}</th>
              <th scope="col" class="p-2">{{ t('sites.endpoints.id') }}</th>
              <th scope="col" class="p-2">{{ t('sites.endpoints.match') }}</th>
              <th scope="col" class="p-2">{{ t('sites.endpoints.methods') }}</th>
              <th scope="col" class="p-2">{{ t('sites.endpoints.overrides') }}</th>
              <th scope="col" class="p-2">
                <span class="sr-only">{{ t('sites.endpoints.actions') }}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in ranked" :key="r.endpoint.id" class="border-b border-sk-border">
              <td class="p-2 font-semibold" data-testid="rank">{{ r.rank }}</td>
              <th scope="row" class="p-2 font-mono text-sm font-normal">
                <RouterLink
                  :to="{
                    name: 'endpoint-detail',
                    params: { site: siteId, endpoint: r.endpoint.id },
                  }"
                  class="text-sk-accent hover:underline"
                >
                  {{ r.endpoint.id }}
                </RouterLink>
              </th>
              <td class="p-2 font-mono text-sm">{{ matchText(r.endpoint) }}</td>
              <td class="p-2">
                {{
                  r.methodBound
                    ? r.endpoint.match.methods?.join(', ')
                    : t('sites.endpoints.anyMethod')
                }}
              </td>
              <td class="p-2">
                {{ t('sites.endpoints.overrideCount', { n: flatten(r.endpoint.policy).length }) }}
              </td>
              <td class="p-2">
                <Button
                  v-if="canWrite"
                  size="small"
                  severity="danger"
                  text
                  :label="t('common.actions.delete')"
                  :aria-label="t('sites.endpoints.deleteNamed', { id: r.endpoint.id })"
                  @click="toDelete = r.endpoint"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <div class="mt-8">
      <RequestTester :site="siteId" />
    </div>
  </template>

  <SkConfirmDialog
    v-if="canWrite"
    :open="toDelete !== undefined"
    danger
    :busy="busy"
    :title="t('sites.endpoints.deleteTitle', { id: toDelete?.id ?? '' })"
    :message="t('sites.endpoints.deleteMessage')"
    :confirm-label="t('common.actions.delete')"
    @update:open="toDelete = undefined"
    @confirm="remove"
  />
</template>
