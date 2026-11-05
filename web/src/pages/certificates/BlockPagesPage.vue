<script setup lang="ts">
import Button from 'openvue/button'
import InputText from 'openvue/inputtext'
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormErrors } from '@/api/fieldErrors'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import BlockPagePreview from './BlockPagePreview.vue'
import { PREVIEW_FIELDS } from './preview'

type BlockPage = components['schemas']['BlockPage']

const { t } = useI18n()
const { client, call } = useApi()
const session = useSessionStore()
const toasts = useToastStore()
const form = useFormErrors({ known: ['id', 'html'] })
const canWrite = session.can('config:write')

const pages = ref<BlockPage[]>([])
const loading = ref(true)
const loadError = ref('')
const slug = ref('')
const html = ref('')
const busy = ref(false)
const formError = ref('')
const editor = ref<HTMLElement>()

const pendingDelete = ref<BlockPage>()
const deleteOpen = ref(false)
const deleteBusy = ref(false)
const deleteError = ref('')

const fieldList = PREVIEW_FIELDS.map((f) => `.${f}`).join(' ')
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    pages.value = (await call(client.GET('/block-pages'), { toast: false })).data.items
  } catch (e) {
    loadError.value = isApiError(e)
      ? (e.detail ?? e.title)
      : t('certificates.blockPages.loadFailed')
  } finally {
    loading.value = false
  }
}
onMounted(load)

function replace(page: BlockPage) {
  slug.value = page.id
  html.value = ''
  form.clear()
  editor.value?.scrollIntoView?.()
}

async function save() {
  if (busy.value) return
  busy.value = true
  formError.value = ''
  form.clear()
  const id = slug.value
  try {
    await call(
      client.PUT('/block-pages/{id}', { params: { path: { id } }, body: { html: html.value } }),
      { toast: false },
    )
    toasts.success(t('certificates.blockPages.saved', { id }))
    slug.value = ''
    html.value = ''
    await load()
  } catch (e) {
    // Template parse/render failures come back as 422 with a message about the template.
    if (!form.apply(e)) {
      formError.value = isApiError(e) ? (e.detail ?? e.title) : t('common.errors.unknown')
    }
  } finally {
    busy.value = false
  }
}

function askDelete(page: BlockPage) {
  pendingDelete.value = page
  deleteError.value = ''
  deleteOpen.value = true
}

async function confirmDelete() {
  const page = pendingDelete.value
  if (!page) return
  deleteBusy.value = true
  deleteError.value = ''
  try {
    await call(client.DELETE('/block-pages/{id}', { params: { path: { id: page.id } } }), {
      toast: false,
    })
    toasts.success(t('certificates.blockPages.deleted', { id: page.id }))
    deleteOpen.value = false
    await load()
  } catch (e) {
    deleteError.value = isApiError(e)
      ? e.kind === 'conflict'
        ? `${t('certificates.blockPages.inUse')} ${e.detail ?? ''}`.trim()
        : (e.detail ?? e.title)
      : t('common.errors.unknown')
  } finally {
    deleteBusy.value = false
  }
}
</script>

<template>
  <SkPageHeader
    :title="t('certificates.blockPages.title')"
    :description="t('certificates.blockPages.description')"
    :breadcrumbs="[
      { label: t('certificates.blockPages.breadcrumbCertificates'), to: '/certificates' },
      { label: t('certificates.blockPages.title') },
    ]"
  />

  <div class="flex flex-col gap-10">
    <section class="flex flex-col gap-3" :aria-label="t('certificates.blockPages.caption')">
      <p v-if="loading" role="status">{{ t('certificates.blockPages.loading') }}</p>
      <div
        v-else-if="loadError"
        role="alert"
        class="flex flex-col items-start gap-2 rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
      >
        <p>
          <i class="ti ti-alert-circle" aria-hidden="true" />
          {{ t('certificates.blockPages.loadFailed') }} {{ loadError }}
        </p>
        <Button :label="t('common.actions.retry')" @click="load" />
      </div>
      <SkEmptyState
        v-else-if="pages.length === 0"
        icon="ti ti-file-off"
        :title="t('certificates.blockPages.emptyTitle')"
        :description="t('certificates.blockPages.emptyDescription')"
      />
      <div
        v-else
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('certificates.blockPages.caption')"
      >
        <table class="w-full text-left text-sm">
          <caption class="sr-only">
            {{
              t('certificates.blockPages.caption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('certificates.blockPages.id') }}</th>
              <th scope="col" class="p-2">{{ t('certificates.blockPages.size') }}</th>
              <th scope="col" class="p-2">{{ t('certificates.blockPages.updated') }}</th>
              <th v-if="canWrite" scope="col" class="p-2">
                {{ t('certificates.blockPages.actions') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="page in pages" :key="page.id" class="border-b border-sk-border">
              <th scope="row" class="p-2 font-mono font-medium">{{ page.id }}</th>
              <td class="p-2">
                {{ t('certificates.blockPages.sizeBytes', { n: page.size_bytes }) }}
              </td>
              <td class="p-2">{{ dateFormat.format(new Date(page.updated_at)) }}</td>
              <td v-if="canWrite" class="flex gap-2 p-2">
                <Button
                  outlined
                  size="small"
                  :label="t('certificates.blockPages.edit')"
                  :aria-label="t('certificates.blockPages.editLabel', { id: page.id })"
                  @click="replace(page)"
                />
                <Button
                  outlined
                  severity="danger"
                  size="small"
                  :label="t('certificates.blockPages.delete')"
                  :aria-label="t('certificates.blockPages.deleteLabel', { id: page.id })"
                  @click="askDelete(page)"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section
      v-if="canWrite"
      ref="editor"
      aria-labelledby="bp-form-heading"
      class="flex max-w-3xl flex-col gap-4"
    >
      <h2 id="bp-form-heading" class="text-lg font-semibold">
        {{ t('certificates.blockPages.formHeading') }}
      </h2>
      <p class="text-sk-muted">{{ t('certificates.blockPages.formIntro') }}</p>
      <form class="flex flex-col gap-4" novalidate @submit.prevent="save">
        <p
          v-if="formError || form.unmatched.value.length"
          role="alert"
          class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
        >
          <i class="ti ti-alert-circle" aria-hidden="true" />
          {{ t('certificates.blockPages.formError') }} {{ formError }}
          <span v-for="m in form.unmatched.value" :key="m" class="block">{{ m }}</span>
        </p>
        <SkFormField
          :label="t('certificates.blockPages.slug')"
          :help="t('certificates.blockPages.slugHelp')"
          :error="form.errorFor('id')"
          required
        >
          <template #default="{ attrs, invalid }">
            <InputText
              v-bind="attrs"
              v-model="slug"
              :invalid="invalid"
              name="id"
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
              pattern="[a-z0-9][a-z0-9\-]{0,62}"
              fluid
              @update:model-value="form.clear('id')"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('certificates.blockPages.html')"
          :help="t('certificates.blockPages.htmlHelp', { fields: fieldList })"
          :error="
            form.errorFor('html')
              ? `${t('certificates.blockPages.templateError')}: ${form.errorFor('html')}`
              : undefined
          "
          required
        >
          <template #default="{ attrs }">
            <textarea
              v-bind="attrs"
              v-model="html"
              name="html"
              rows="12"
              maxlength="65536"
              spellcheck="false"
              class="w-full rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2 font-mono text-sm text-sk-text"
              @input="form.clear('html')"
            />
          </template>
        </SkFormField>
        <div>
          <Button
            type="submit"
            :label="busy ? t('certificates.blockPages.saving') : t('certificates.blockPages.save')"
            :loading="busy"
          />
        </div>
      </form>
      <h3 class="text-base font-semibold">{{ t('certificates.blockPages.preview') }}</h3>
      <p class="text-sm text-sk-muted">{{ t('certificates.blockPages.previewHelp') }}</p>
      <BlockPagePreview :html="html" />
    </section>
    <p v-else class="text-sk-muted">
      <i class="ti ti-lock" aria-hidden="true" />
      {{ t('certificates.blockPages.readOnly') }}
    </p>
  </div>

  <SkConfirmDialog
    v-model:open="deleteOpen"
    danger
    :busy="deleteBusy"
    :title="t('certificates.blockPages.deleteTitle', { id: pendingDelete?.id ?? '' })"
    :message="t('certificates.blockPages.deleteMessage')"
    :confirm-label="t('certificates.blockPages.deleteConfirm')"
    @confirm="confirmDelete"
  >
    <p v-if="deleteError" role="alert" class="text-sk-danger">
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ deleteError }}
    </p>
  </SkConfirmDialog>
</template>
