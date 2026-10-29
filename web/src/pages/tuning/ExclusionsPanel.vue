<script setup lang="ts">
import Button from 'openvue/button'
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import { useToastStore } from '@/stores/toasts'
import { removalParts, scopeMethods, scopePaths, type Exclusion } from './lib'

const props = defineProps<{ site: string; canWrite: boolean }>()
const emit = defineEmits<{ stale: [] }>()

const { t } = useI18n()
const { client, call, ifMatch } = useApi()
const toasts = useToastStore()

const items = ref<Exclusion[]>([])
const etag = ref<string>()
const state = ref<'loading' | 'ready' | 'error'>('loading')
const toDelete = ref<Exclusion>()
const busy = ref(false)

async function load() {
  state.value = 'loading'
  try {
    const res = await call(
      client.GET('/sites/{site}/exclusions', { params: { path: { site: props.site } } }),
      { toast: false },
    )
    items.value = res.data.items
    etag.value = res.etag
    state.value = 'ready'
  } catch (e) {
    if (!isApiError(e)) throw e
    state.value = 'error'
  }
}
onMounted(load)

async function remove() {
  const target = toDelete.value
  if (!target || !etag.value) return
  busy.value = true
  try {
    await call(
      client.DELETE('/sites/{site}/exclusions/{exclusion}', {
        params: {
          path: { site: props.site, exclusion: target.id },
          header: ifMatch(etag.value),
        },
      }),
      { toast: false },
    )
    toasts.success(t('tuning.exclusions.deleted', { id: target.id }))
    toDelete.value = undefined
    await load()
  } catch (e) {
    if (!isApiError(e)) throw e
    toDelete.value = undefined
    if (e.kind === 'stale' || e.kind === 'precondition_required') emit('stale')
    else toasts.error(e)
  } finally {
    busy.value = false
  }
}

defineExpose({ load })
</script>

<template>
  <section aria-labelledby="tn-exclusions" class="rounded-sk-lg border border-sk-border p-4">
    <h2 id="tn-exclusions" class="mb-1 text-lg font-semibold">
      {{ t('tuning.exclusions.title') }}
    </h2>
    <p class="mb-3 text-sk-muted">{{ t('tuning.exclusions.help') }}</p>

    <p v-if="state === 'loading'" role="status">{{ t('common.loading') }}…</p>
    <div v-else-if="state === 'error'" role="alert" class="text-sk-danger">
      {{ t('tuning.exclusions.loadFailed') }}
      <Button :label="t('common.actions.retry')" severity="secondary" @click="load" />
    </div>
    <p v-else-if="!items.length" data-testid="exclusions-empty" class="text-sk-muted">
      {{ t('tuning.exclusions.empty') }}
    </p>
    <div
      v-else
      class="overflow-x-auto"
      tabindex="0"
      role="region"
      :aria-label="t('tuning.exclusions.scroll')"
    >
      <table class="w-full text-left text-sm" data-testid="exclusions-table">
        <caption class="sr-only">
          {{
            t('tuning.exclusions.caption')
          }}
        </caption>
        <thead>
          <tr class="border-b border-sk-border-strong">
            <th scope="col" class="p-2">{{ t('tuning.exclusions.cols.id') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.exclusions.cols.description') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.exclusions.cols.scope') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.exclusions.cols.removes') }}</th>
            <th scope="col" class="p-2">
              <span class="sr-only">{{ t('tuning.exclusions.cols.actions') }}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="ex in items" :key="ex.id" class="border-b border-sk-border align-top">
            <th scope="row" class="break-all p-2 font-mono font-normal">{{ ex.id }}</th>
            <td class="p-2">{{ ex.description }}</td>
            <td class="break-all p-2 font-mono">
              {{ scopePaths(ex).join(', ') || t('tuning.exclusions.allPaths') }};
              {{ scopeMethods(ex).join(', ') || t('tuning.exclusions.allMethods') }}
            </td>
            <td class="break-all p-2 font-mono">
              <span v-for="(p, n) in removalParts(ex)" :key="n" class="block">
                {{ t(`tuning.exclusions.${p.key}`, p.params) }}
              </span>
            </td>
            <td class="p-2">
              <Button
                v-if="canWrite"
                size="small"
                severity="danger"
                text
                :label="t('tuning.exclusions.delete')"
                :aria-label="t('tuning.exclusions.deleteNamed', { id: ex.id })"
                @click="toDelete = ex"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="mt-3 text-sm text-sk-muted">
      <i class="ti ti-info-circle" aria-hidden="true" /> {{ t('tuning.exclusions.inherited') }}
    </p>

    <SkConfirmDialog
      v-if="canWrite"
      :open="toDelete !== undefined"
      danger
      :busy="busy"
      :title="t('tuning.exclusions.deleteTitle', { id: toDelete?.id ?? '' })"
      :message="t('tuning.exclusions.deleteMessage')"
      :confirm-label="t('tuning.exclusions.delete')"
      @update:open="toDelete = undefined"
      @confirm="remove"
    />
  </section>
</template>
