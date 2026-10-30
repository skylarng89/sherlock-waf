<script setup lang="ts">
import Button from 'openvue/button'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormErrors } from '@/api/fieldErrors'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkFormField from '@/components/SkFormField.vue'
import ListControl from '@/pages/sites/controls/ListControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { clone } from '@/pages/sites/lib/json'
import { useWriteFlow } from '@/pages/sites/lib/useWriteFlow'
import WriteBanners from '@/pages/sites/WriteBanners.vue'
import { useToastStore } from '@/stores/toasts'
import { listReferences } from './references'
import type { GlobalConfigStore, IpList } from './useGlobalConfig'

const props = defineProps<{ store: GlobalConfigStore; canWrite: boolean }>()
const { t } = useI18n()
const toasts = useToastStore()

interface Draft extends IpList {
  /** Lists created in this session: their name can still be chosen. */
  isNew?: boolean
}

const lists = ref<Draft[]>([])
const busy = ref(false)
const toDelete = ref<number>()
const blocked = ref<{ name: string; refs: string[] }>()

// Everything the server says is shown: per-list errors inline, the rest in the summary.
const form = useFormErrors({})
const flow = useWriteFlow({
  form,
  rebase: () => ({ prefixes: ['/global/ip_lists'] }),
})

function sync() {
  lists.value = clone(props.store.config.value.global?.ip_lists ?? [])
}
watch(() => props.store.config.value, sync, { immediate: true })

const references = computed(() => listReferences(props.store.config.value))
const total = computed(() => lists.value.reduce((n, l) => n + l.cidrs.length, 0))

/** Messages of `i.cidrs.<n>` as {entry number, value, message}. */
function cidrErrors(index: number) {
  const prefix = `${index}.cidrs.`
  return Object.entries(form.errors.value)
    .filter(([path]) => path.startsWith(prefix))
    .map(([path, message]) => {
      const entry = Number(path.slice(prefix.length)) + 1
      return { entry, value: lists.value[index]?.cidrs[entry - 1] ?? '', message }
    })
}

const otherErrors = computed(() =>
  Object.entries(form.errors.value)
    .filter(([path]) => !/^\d+\.(name|cidrs(\.\d+)?)$/.test(path))
    .map(([path, message]) => (path ? `${path}: ${message}` : message)),
)

function add() {
  lists.value = [...lists.value, { name: '', cidrs: [], isNew: true }]
}

function clean(): IpList[] {
  return lists.value.map(({ name, cidrs }) => ({ name: name.trim(), cidrs }))
}

async function persist(next: IpList[]): Promise<boolean> {
  flow.reset()
  busy.value = true
  try {
    await props.store.save((draft) => {
      draft.global = { ...draft.global, ip_lists: next }
    })
    return true
  } catch (e) {
    flow.handle(e)
    return false
  } finally {
    busy.value = false
  }
}

async function save() {
  if (await persist(clean())) {
    sync()
    toasts.success(t('access.lists.saved'))
  }
}

function askDelete(index: number) {
  const list = lists.value[index]
  if (!list) return
  const refs = list.isNew ? [] : (references.value.get(list.name) ?? [])
  if (refs.length) {
    blocked.value = { name: list.name, refs }
    return
  }
  blocked.value = undefined
  if (list.isNew) lists.value = lists.value.filter((_, i) => i !== index)
  else toDelete.value = index
}

async function remove() {
  const index = toDelete.value
  const target = index === undefined ? undefined : lists.value[index]
  toDelete.value = undefined
  if (!target) return
  const next = clean().filter((l) => l.name !== target.name.trim())
  if (await persist(next)) {
    sync()
    toasts.success(t('access.lists.deleted', { name: target.name }))
  }
}

// Reload offered by the banner re-reads the whole document, which resets the drafts.
async function reload() {
  flow.reset()
  await props.store.load()
}
</script>

<template>
  <section class="flex flex-col gap-4" aria-labelledby="ip-lists-title">
    <div>
      <h2 id="ip-lists-title" class="text-lg font-semibold">{{ t('access.lists.title') }}</h2>
      <p class="text-sk-muted">{{ t('access.lists.description') }}</p>
    </div>

    <WriteBanners
      :stale="flow.stale.value"
      :precondition="flow.precondition.value"
      :unmatched="[...form.unmatched.value, ...otherErrors]"
      @reload="reload"
    />

    <div
      v-if="blocked"
      role="alert"
      class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
      data-testid="delete-blocked"
    >
      <p class="font-medium">
        <i class="ti ti-ban" aria-hidden="true" />
        {{ t('access.lists.blocked', { name: blocked.name }) }}
      </p>
      <ul class="list-disc pl-6">
        <li v-for="r in blocked.refs" :key="r">{{ r }}</li>
      </ul>
      <button type="button" class="mt-2 underline" @click="blocked = undefined">
        {{ t('common.actions.dismiss') }}
      </button>
    </div>

    <SkEmptyState
      v-if="lists.length === 0"
      icon="ti ti-list-details"
      :title="t('access.lists.emptyTitle')"
      :description="t('access.lists.emptyDescription')"
    />

    <form class="flex flex-col gap-4" novalidate data-testid="ip-lists-form" @submit.prevent="save">
      <fieldset
        v-for="(list, i) in lists"
        :key="i"
        class="flex flex-col gap-3 rounded-sk border border-sk-border p-4"
        :disabled="!canWrite"
        :data-testid="`ip-list-${list.name || 'new'}`"
      >
        <legend class="px-1 font-semibold">
          {{ list.name || t('access.lists.unnamed') }}
          <span class="ml-2 text-sm font-normal text-sk-muted">
            {{ t('access.lists.entries', { count: list.cidrs.length }, list.cidrs.length) }}
          </span>
          <span
            v-if="list.isNew"
            class="ml-2 rounded-full bg-sk-info-bg px-2 py-0.5 text-xs font-normal text-sk-info"
          >
            <i class="ti ti-sparkles" aria-hidden="true" />
            {{ t('access.lists.unsaved') }}
          </span>
        </legend>
        <SkFormField
          :label="t('access.lists.name')"
          :help="list.isNew ? t('access.lists.nameHelp') : t('access.lists.nameLocked')"
          :error="form.errorFor(`${i}.name`)"
          required
        >
          <template #default="{ attrs, invalid }">
            <TextControl
              v-bind="attrs"
              v-model="list.name"
              mono
              :disabled="!list.isNew || !canWrite"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="form.clear(`${i}.name`)"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('access.lists.cidrs')"
          :help="t('access.lists.cidrsHelp')"
          :error="form.errorFor(`${i}.cidrs`)"
        >
          <template #default="{ attrs, invalid }">
            <ListControl
              v-bind="attrs"
              v-model="list.cidrs"
              :rows="6"
              :aria-invalid="invalid || cidrErrors(i).length > 0 ? 'true' : undefined"
            />
          </template>
        </SkFormField>
        <ul v-if="cidrErrors(i).length" role="alert" class="text-sm text-sk-danger">
          <li v-for="e in cidrErrors(i)" :key="e.entry">
            <i class="ti ti-alert-circle" aria-hidden="true" />
            {{
              t('access.lists.cidrError', { entry: e.entry, value: e.value, message: e.message })
            }}
          </li>
        </ul>
        <div v-if="canWrite">
          <Button
            type="button"
            severity="danger"
            icon="ti ti-trash"
            :label="t('access.lists.delete')"
            :aria-label="
              t('access.lists.deleteNamed', { name: list.name || t('access.lists.unnamed') })
            "
            @click="askDelete(i)"
          />
        </div>
      </fieldset>

      <div v-if="canWrite" class="flex flex-wrap items-center gap-2">
        <Button
          type="button"
          severity="secondary"
          icon="ti ti-plus"
          :label="t('access.lists.add')"
          @click="add"
        />
        <Button
          type="submit"
          :label="t('access.lists.save')"
          :loading="busy"
          :disabled="busy || lists.length === 0"
        />
        <p class="text-sm text-sk-muted">{{ t('access.lists.total', { count: total }) }}</p>
      </div>
    </form>

    <SkConfirmDialog
      v-if="canWrite"
      :open="toDelete !== undefined"
      danger
      :busy="busy"
      :title="t('access.lists.confirmTitle', { name: lists[toDelete ?? -1]?.name ?? '' })"
      :message="t('access.lists.confirmMessage')"
      :confirm-label="t('access.lists.delete')"
      @update:open="toDelete = undefined"
      @confirm="remove"
    />
  </section>
</template>
