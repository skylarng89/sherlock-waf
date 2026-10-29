<script setup lang="ts">
import Button from 'openvue/button'
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterLink } from 'vue-router'
import type { components } from '@/api/schema'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SkStatusBadge from '@/components/SkStatusBadge.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import { expiryOf } from './expiry'
import UploadCertificateForm from './UploadCertificateForm.vue'

type Certificate = components['schemas']['Certificate']
type AcmeStatus = components['schemas']['ACMEStatus']

const { t } = useI18n()
const { client, call } = useApi()
const session = useSessionStore()
const toasts = useToastStore()

const certificates = ref<Certificate[]>([])
const acme = ref<AcmeStatus[]>([])
const loading = ref(true)
const loadError = ref('')
const acmeError = ref('')
const canWrite = session.can('config:write')

const pendingDelete = ref<Certificate>()
const deleteOpen = ref(false)
const deleteBusy = ref(false)
const deleteError = ref('')

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const fmt = (iso: string | null | undefined) => (iso ? dateFormat.format(new Date(iso)) : '')

function message(e: unknown): string {
  return isApiError(e) ? (e.detail ?? e.title) : t('certificates.loadFailed')
}

async function load() {
  loading.value = true
  loadError.value = ''
  acmeError.value = ''
  const [certs, status] = await Promise.allSettled([
    call(client.GET('/certificates'), { toast: false }),
    call(client.GET('/certificates/acme-status'), { toast: false }),
  ])
  if (certs.status === 'fulfilled') certificates.value = certs.value.data.items
  else loadError.value = message(certs.reason)
  if (status.status === 'fulfilled') acme.value = status.value.data.items
  else acmeError.value = message(status.reason)
  loading.value = false
}

onMounted(load)

function askDelete(cert: Certificate) {
  pendingDelete.value = cert
  deleteError.value = ''
  deleteOpen.value = true
}

async function confirmDelete() {
  const cert = pendingDelete.value
  if (!cert) return
  deleteBusy.value = true
  deleteError.value = ''
  try {
    await call(client.DELETE('/certificates/{id}', { params: { path: { id: cert.id } } }), {
      toast: false,
    })
    toasts.success(t('certificates.delete.done', { name: cert.name }))
    deleteOpen.value = false
    await load()
  } catch (e) {
    deleteError.value = isApiError(e)
      ? e.kind === 'conflict'
        ? `${t('certificates.delete.inUse')} ${e.detail ?? ''}`.trim()
        : (e.detail ?? e.title)
      : t('common.errors.unknown')
  } finally {
    deleteBusy.value = false
  }
}

const now = () => Date.now()
</script>

<template>
  <SkPageHeader :title="t('certificates.title')" :description="t('certificates.description')" />

  <div class="flex flex-col gap-10">
    <section aria-labelledby="cert-list-heading" class="flex flex-col gap-3">
      <h2 id="cert-list-heading" class="text-lg font-semibold">
        {{ t('certificates.list.heading') }}
      </h2>
      <p v-if="loading" role="status">{{ t('certificates.list.loading') }}</p>
      <div
        v-else-if="loadError"
        role="alert"
        class="flex flex-col items-start gap-2 rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
      >
        <p>
          <i class="ti ti-alert-circle" aria-hidden="true" />
          {{ t('certificates.loadFailed') }} {{ loadError }}
        </p>
        <Button :label="t('common.actions.retry')" @click="load" />
      </div>
      <SkEmptyState
        v-else-if="certificates.length === 0"
        icon="ti ti-certificate-off"
        :title="t('certificates.list.emptyTitle')"
        :description="t('certificates.list.emptyDescription')"
      />
      <div
        v-else
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('certificates.list.caption')"
      >
        <table class="w-full text-left text-sm">
          <caption class="sr-only">
            {{
              t('certificates.list.caption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('certificates.list.name') }}</th>
              <th scope="col" class="p-2">{{ t('certificates.list.hosts') }}</th>
              <th scope="col" class="p-2">{{ t('certificates.list.issuer') }}</th>
              <th scope="col" class="p-2">{{ t('certificates.list.validFrom') }}</th>
              <th scope="col" class="p-2">{{ t('certificates.list.validUntil') }}</th>
              <th v-if="canWrite" scope="col" class="p-2">
                {{ t('certificates.list.actions') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="cert in certificates"
              :key="cert.id"
              class="border-b border-sk-border align-top"
              :data-testid="`cert-${cert.id}`"
            >
              <th scope="row" class="p-2 font-medium">{{ cert.name }}</th>
              <td class="p-2">{{ cert.hosts.join(', ') }}</td>
              <td class="p-2">{{ cert.issuer }}</td>
              <td class="p-2">{{ fmt(cert.not_before) }}</td>
              <td class="flex flex-col items-start gap-1 p-2">
                <span>{{ fmt(cert.not_after) }}</span>
                <template v-for="exp in [expiryOf(cert.not_after, now())]" :key="exp.state">
                  <SkStatusBadge
                    v-if="exp.state === 'expired'"
                    state="error"
                    :label="t('certificates.expiry.expired')"
                  />
                  <SkStatusBadge
                    v-else-if="exp.state === 'warning'"
                    state="warn"
                    :label="
                      exp.days < 1
                        ? t('certificates.expiry.warningToday')
                        : t('certificates.expiry.warning', { days: exp.days })
                    "
                  />
                  <SkStatusBadge
                    v-else
                    state="ok"
                    :label="t('certificates.expiry.ok', { days: exp.days })"
                  />
                </template>
              </td>
              <td v-if="canWrite" class="p-2">
                <Button
                  severity="danger"
                  outlined
                  size="small"
                  :label="t('certificates.list.delete')"
                  :aria-label="t('certificates.list.deleteLabel', { name: cert.name })"
                  @click="askDelete(cert)"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <UploadCertificateForm v-if="canWrite" @uploaded="load" />
    <p v-else class="text-sk-muted">
      <i class="ti ti-lock" aria-hidden="true" />
      {{ t('certificates.upload.readOnly') }}
    </p>

    <section aria-labelledby="acme-heading" class="flex flex-col gap-3">
      <h2 id="acme-heading" class="text-lg font-semibold">{{ t('certificates.acme.heading') }}</h2>
      <p v-if="loading" role="status">{{ t('certificates.acme.loading') }}</p>
      <p v-else-if="acmeError" role="alert" class="text-sk-danger">
        <i class="ti ti-alert-circle" aria-hidden="true" />
        {{ t('certificates.loadFailed') }} {{ acmeError }}
      </p>
      <SkEmptyState
        v-else-if="acme.length === 0"
        icon="ti ti-lock-open-off"
        :title="t('certificates.acme.emptyTitle')"
        :description="t('certificates.acme.emptyDescription')"
      />
      <div
        v-else
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('certificates.acme.caption')"
      >
        <table class="w-full text-left text-sm">
          <caption class="sr-only">
            {{
              t('certificates.acme.caption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('certificates.acme.site') }}</th>
              <th scope="col" class="p-2">{{ t('certificates.acme.host') }}</th>
              <th scope="col" class="p-2">{{ t('certificates.acme.state') }}</th>
              <th scope="col" class="p-2">{{ t('certificates.acme.validUntil') }}</th>
              <th scope="col" class="p-2">{{ t('certificates.acme.explanation') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in acme"
              :key="`${row.site}/${row.host}`"
              class="border-b border-sk-border align-top"
            >
              <td class="p-2">{{ row.site }}</td>
              <th scope="row" class="p-2 font-medium">{{ row.host }}</th>
              <td class="p-2">
                <SkStatusBadge
                  :state="row.state === 'issued' ? 'ok' : row.state === 'failed' ? 'error' : 'warn'"
                  :label="t(`certificates.acme.states.${row.state}`)"
                />
              </td>
              <td class="p-2">
                {{ row.not_after ? fmt(row.not_after) : t('certificates.acme.notAfterUnknown') }}
              </td>
              <td class="p-2">
                {{ t(`certificates.acme.explain.${row.state}`) }}
                <span v-if="row.detail" class="block text-sk-muted">{{ row.detail }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section aria-labelledby="bp-link-heading" class="flex flex-col gap-2">
      <h2 id="bp-link-heading" class="text-lg font-semibold">
        {{ t('certificates.blockPagesLink.heading') }}
      </h2>
      <p class="text-sk-muted">{{ t('certificates.blockPagesLink.text') }}</p>
      <RouterLink to="/certificates/block-pages" class="w-fit font-medium text-sk-accent underline">
        {{ t('certificates.blockPagesLink.link') }}
      </RouterLink>
    </section>
  </div>

  <SkConfirmDialog
    v-model:open="deleteOpen"
    danger
    :busy="deleteBusy"
    :title="t('certificates.delete.title', { name: pendingDelete?.name ?? '' })"
    :message="t('certificates.delete.message')"
    :confirm-label="t('certificates.delete.confirm')"
    @confirm="confirmDelete"
  >
    <p v-if="deleteError" role="alert" class="text-sk-danger">
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ deleteError }}
    </p>
  </SkConfirmDialog>
</template>
