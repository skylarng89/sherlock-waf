<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SkStatusBadge from '@/components/SkStatusBadge.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'

type Catalogue = components['schemas']['VirtualPatchCatalogue']
type SiteState = components['schemas']['VirtualPatchSiteState']

const STATE_ICON: Record<SiteState['state'], string> = {
  active: 'ti ti-shield-check',
  stack_not_declared: 'ti ti-stack-2',
  disabled: 'ti ti-ban',
  pack_off: 'ti ti-power',
}

const { t } = useI18n()
const { client, call, ifMatch } = useApi()
const session = useSessionStore()
const toasts = useToastStore()
const canWrite = computed(() => session.can('config:write'))

const filters = reactive({ q: '', site: '', severity: '', kev: false })
const sites = ref<string[]>([])
const etag = ref<string>()
const data = ref<Catalogue>()
const state = ref<'loading' | 'ready' | 'error'>('loading')
const busyKey = ref<string>()

async function loadSites() {
  try {
    const res = await call(client.GET('/sites'), { toast: false })
    sites.value = res.data.items.map((s) => s.id)
    etag.value = res.etag
  } catch (e) {
    if (!isApiError(e)) throw e
  }
}

async function load() {
  state.value = 'loading'
  try {
    const res = await call(
      client.GET('/virtual-patches', {
        params: {
          query: {
            ...(filters.q ? { q: filters.q } : {}),
            ...(filters.site ? { site: filters.site } : {}),
            ...(filters.severity
              ? { severity: filters.severity as 'low' | 'medium' | 'high' | 'critical' }
              : {}),
            ...(filters.kev ? { kev: true } : {}),
          },
        },
      }),
      { toast: false },
    )
    data.value = res.data
    state.value = 'ready'
  } catch (e) {
    if (!isApiError(e)) throw e
    state.value = 'error'
  }
}
onMounted(async () => {
  await loadSites()
  await load()
})

async function toggle(patch: string, s: SiteState, enabled: boolean) {
  if (!etag.value) return
  busyKey.value = `${patch}/${s.site}`
  try {
    await call(
      client.PUT('/sites/{site}/virtual-patches/{patch}', {
        params: { path: { site: s.site, patch }, header: ifMatch(etag.value) },
        body: { enabled },
      }),
      { toast: false },
    )
    toasts.success(
      t('tuning.vp.switched', {
        patch,
        site: s.site,
        state: enabled ? t('tuning.vp.on') : t('tuning.vp.off'),
      }),
    )
    await loadSites()
    await load()
  } catch (e) {
    if (!isApiError(e)) throw e
    toasts.error(e)
    // A stale version is the usual cause; refresh so the next try carries the new one.
    await loadSites()
    await load()
  } finally {
    busyKey.value = undefined
  }
}

const field = 'rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2'
const sevClass = (s: string) =>
  s === 'critical' || s === 'high' ? 'text-sk-danger' : s === 'medium' ? 'text-sk-warning' : ''
</script>

<template>
  <SkPageHeader :title="t('tuning.vp.title')" :description="t('tuning.vp.description')" />

  <form class="mb-4 flex flex-wrap items-end gap-3" role="search" @submit.prevent="load">
    <div class="flex flex-col gap-1">
      <label for="vp-q" class="text-sm font-medium">{{ t('tuning.vp.search') }}</label>
      <input id="vp-q" v-model="filters.q" type="search" :class="field" autocomplete="off" />
    </div>
    <div class="flex flex-col gap-1">
      <label for="vp-site" class="text-sm font-medium">{{ t('tuning.crs.site') }}</label>
      <select id="vp-site" v-model="filters.site" :class="field">
        <option value="">{{ t('tuning.crs.noSite') }}</option>
        <option v-for="s in sites" :key="s" :value="s">{{ s }}</option>
      </select>
    </div>
    <div class="flex flex-col gap-1">
      <label for="vp-sev" class="text-sm font-medium">{{ t('tuning.vp.severity') }}</label>
      <select id="vp-sev" v-model="filters.severity" :class="field">
        <option value="">{{ t('tuning.vp.anySeverity') }}</option>
        <option v-for="s in ['critical', 'high', 'medium', 'low']" :key="s" :value="s">
          {{ t(`tuning.vp.sev.${s}`) }}
        </option>
      </select>
    </div>
    <label class="flex items-center gap-2 py-2">
      <input v-model="filters.kev" type="checkbox" class="size-4" />
      {{ t('tuning.vp.kevOnly') }}
    </label>
    <Button type="submit" :label="t('tuning.vp.apply')" />
  </form>

  <div role="status" aria-live="polite">
    <p v-if="state === 'loading'">{{ t('tuning.vp.loading') }}…</p>
  </div>
  <div v-if="state === 'error'" role="alert" class="text-sk-danger">
    {{ t('tuning.vp.loadFailed') }}
    <Button :label="t('common.actions.retry')" severity="secondary" @click="load" />
  </div>

  <template v-else-if="data">
    <p class="mb-2 text-sk-muted">
      {{ t('tuning.vp.pack', { version: data.pack_version, days: data.window_days }) }}
    </p>
    <p v-if="data.truncated" class="mb-2 text-sm text-sk-muted">{{ t('tuning.vp.truncated') }}</p>

    <SkEmptyState v-if="!data.items.length" :title="t('tuning.vp.empty')" icon="ti ti-shield-off" />
    <div
      v-else
      class="overflow-x-auto"
      tabindex="0"
      role="region"
      :aria-label="t('tuning.vp.scroll')"
    >
      <table class="w-full text-left text-sm" data-testid="vp-table">
        <caption class="sr-only">
          {{
            t('tuning.vp.caption')
          }}
        </caption>
        <thead>
          <tr class="border-b border-sk-border-strong">
            <th scope="col" class="p-2">{{ t('tuning.vp.cols.patch') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.vp.cols.cve') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.vp.cols.product') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.vp.cols.severity') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.vp.cols.stacks') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.vp.cols.sites') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.vp.cols.hits') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in data.items" :key="p.id" class="border-b border-sk-border align-top">
            <th scope="row" class="p-2 font-normal">
              <span class="block font-mono">{{ p.id }}</span>
              <span class="block">{{ p.title }}</span>
              <details class="mt-1">
                <summary class="cursor-pointer text-sk-accent">
                  {{ t('tuning.vp.details', { patch: p.id }) }}
                </summary>
                <p class="mt-1">
                  {{
                    p.verification === 'synthetic'
                      ? t('tuning.vp.synthetic')
                      : t('tuning.vp.productVerified')
                  }}
                  · {{ p.versions }}
                </p>
                <p v-if="p.false_positive_notes" class="mt-1">
                  <strong>{{ t('tuning.vp.notes') }}:</strong> {{ p.false_positive_notes }}
                </p>
                <template v-if="p.references.length">
                  <p class="mt-1 font-medium">{{ t('tuning.vp.references') }}</p>
                  <ul>
                    <li v-for="r in p.references" :key="r" class="break-all font-mono">{{ r }}</li>
                  </ul>
                </template>
              </details>
            </th>
            <td class="p-2">
              <span v-for="c in p.cves" :key="c" class="block font-mono">{{ c }}</span>
              <span v-if="p.kev" class="mt-1 inline-block" :title="t('tuning.vp.kevHelp')">
                <SkStatusBadge state="error" :label="t('tuning.vp.kev')" />
              </span>
            </td>
            <td class="p-2">{{ p.vendor }} {{ p.product }}</td>
            <td class="p-2" :class="sevClass(p.severity)">
              {{ t(`tuning.vp.sev.${p.severity}`) }}
              <span class="block text-sk-muted">{{ t('tuning.vp.cvss', { score: p.cvss }) }}</span>
            </td>
            <td class="p-2">
              {{ p.generic ? t('tuning.vp.generic') : p.stacks.join(', ') }}
            </td>
            <td class="p-2">
              <ul class="flex flex-col gap-2">
                <li v-for="s in p.sites" :key="s.site" class="flex flex-wrap items-center gap-2">
                  <span class="font-mono">{{ s.site }}</span>
                  <span class="whitespace-nowrap font-medium" data-testid="vp-state">
                    <i :class="STATE_ICON[s.state]" aria-hidden="true" />
                    {{ t(`tuning.vp.states.${s.state}`) }}
                  </span>
                  <label v-if="canWrite" class="flex items-center gap-1">
                    <input
                      type="checkbox"
                      role="switch"
                      class="size-4"
                      :checked="s.state !== 'disabled'"
                      :disabled="s.state === 'pack_off' || busyKey === `${p.id}/${s.site}`"
                      :aria-label="t('tuning.vp.toggleNamed', { patch: p.id, site: s.site })"
                      @change="toggle(p.id, s, ($event.target as HTMLInputElement).checked)"
                    />
                    <span class="sr-only">{{ t('tuning.vp.toggle', { site: s.site }) }}</span>
                  </label>
                  <span
                    v-if="s.state === 'stack_not_declared'"
                    class="w-full text-xs text-sk-muted"
                  >
                    {{ t('tuning.vp.stackHelp') }}
                  </span>
                </li>
              </ul>
            </td>
            <td class="p-2 font-mono" data-testid="vp-hits">{{ p.hits }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <section v-if="data.covered.length" aria-labelledby="vp-covered" class="mt-8">
      <h2 id="vp-covered" class="mb-2 text-lg font-semibold">{{ t('tuning.vp.covered.title') }}</h2>
      <div
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('tuning.vp.covered.caption')"
      >
        <table class="w-full text-left text-sm" data-testid="covered-table">
          <caption class="sr-only">
            {{
              t('tuning.vp.covered.caption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('tuning.vp.covered.cve') }}</th>
              <th scope="col" class="p-2">{{ t('tuning.vp.covered.product') }}</th>
              <th scope="col" class="p-2">{{ t('tuning.vp.cols.severity') }}</th>
              <th scope="col" class="p-2">{{ t('tuning.vp.covered.rules') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in data.covered" :key="c.cve" class="border-b border-sk-border">
              <th scope="row" class="p-2 font-mono font-normal">
                {{ c.cve }}
                <SkStatusBadge v-if="c.kev" state="error" :label="t('tuning.vp.kev')" />
              </th>
              <td class="p-2">{{ c.product }}</td>
              <td class="p-2">{{ c.severity }}</td>
              <td class="p-2 font-mono">{{ c.crs_rules.join(', ') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </template>
</template>
