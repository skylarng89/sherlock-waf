<script setup lang="ts">
import Button from 'openvue/button'
import { onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SkStatusBadge from '@/components/SkStatusBadge.vue'
import { useSessionStore } from '@/stores/session'
import type { Site } from './lib/siteDraft'
import { useSiteContext } from './lib/useSiteContext'

const { t } = useI18n()
const router = useRouter()
const session = useSessionStore()
const ctx = useSiteContext(() => undefined)

onMounted(ctx.load)

function modeOf(site: Site) {
  return site.policy?.mode ?? ctx.defaults.value.mode ?? 'off'
}
</script>

<template>
  <SkPageHeader :title="t('sites.title')" :description="t('sites.description')">
    <template #actions>
      <Button
        v-if="session.can('config:write')"
        :label="t('sites.add')"
        icon="ti ti-plus"
        @click="router.push({ name: 'site-new' })"
      />
    </template>
  </SkPageHeader>

  <p v-if="ctx.state.value === 'loading'" role="status">{{ t('common.loading') }}…</p>

  <div
    v-else-if="ctx.state.value === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    <p>
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ t('sites.loadFailed') }}
    </p>
    <Button :label="t('common.actions.retry')" severity="secondary" @click="ctx.load" />
  </div>

  <SkEmptyState
    v-else-if="ctx.sites.value.length === 0"
    :title="t('sites.empty.title')"
    :description="t('sites.empty.description')"
    icon="ti ti-world-off"
  >
    <Button
      v-if="session.can('config:write')"
      :label="t('sites.add')"
      @click="router.push({ name: 'site-new' })"
    />
  </SkEmptyState>

  <div
    v-else
    class="overflow-x-auto"
    tabindex="0"
    :aria-label="t('sites.table.scroll')"
    role="region"
  >
    <table class="w-full text-left">
      <caption class="sr-only">
        {{
          t('sites.table.caption')
        }}
      </caption>
      <thead>
        <tr class="border-b border-sk-border-strong">
          <th scope="col" class="p-2">{{ t('sites.table.name') }}</th>
          <th scope="col" class="p-2">{{ t('sites.table.hosts') }}</th>
          <th scope="col" class="p-2">{{ t('sites.table.mode') }}</th>
          <th scope="col" class="p-2">{{ t('sites.table.tls') }}</th>
          <th scope="col" class="p-2">{{ t('sites.table.upstreams') }}</th>
          <th scope="col" class="p-2">{{ t('sites.table.blocks') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="site in ctx.sites.value" :key="site.id" class="border-b border-sk-border">
          <th scope="row" class="p-2 font-medium">
            <RouterLink
              :to="{ name: 'site-detail', params: { site: site.id } }"
              class="text-sk-accent hover:underline"
            >
              {{ site.name || site.id }}
            </RouterLink>
            <span v-if="site.name" class="block font-mono text-sm font-normal text-sk-muted">
              {{ site.id }}
            </span>
          </th>
          <td class="p-2">{{ site.hosts.join(', ') }}</td>
          <td class="p-2"><SkStatusBadge :mode="modeOf(site)" /></td>
          <td class="p-2">{{ t(`sites.options.tlsMode.${site.tls?.mode ?? 'acme'}`) }}</td>
          <td class="p-2">{{ site.upstreams.targets.length }}</td>
          <td class="p-2">
            <span aria-hidden="true">—</span>
            <span class="sr-only">{{ t('sites.table.blocksUnavailable') }}</span>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
