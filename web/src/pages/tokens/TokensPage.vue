<script setup lang="ts">
import Button from 'openvue/button'
import InputText from 'openvue/inputtext'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import { useFormErrors } from '@/api/fieldErrors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'

type Token = components['schemas']['Token']
type Scope = Token['scopes'][number]

const SCOPES: Scope[] = ['read', 'write', 'events:read', 'admin']
const RENDERED = ['name', 'scopes', 'expires_at']

const { t } = useI18n()
const { client, call } = useApi()
const session = useSessionStore()
const toasts = useToastStore()
const form = useFormErrors()

const tokens = ref<Token[]>([])
const loading = ref(true)
const loadError = ref('')
const showOwner = computed(() => session.can('users:manage'))

const name = ref('')
const scopes = ref<Scope[]>([])
const cidrText = ref('')
const expires = ref('')
const busy = ref(false)
const formError = ref('')

// The one-time secret lives only here and is dropped when the dialog closes or the page unmounts.
const secret = ref('')
const secretName = ref('')
const secretOpen = ref(false)
const copyStatus = ref('')

const pendingRevoke = ref<Token>()
const revokeOpen = ref(false)
const revokeBusy = ref(false)
const revokeError = ref('')

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const fmt = (iso: string | null | undefined, empty: string) =>
  iso ? dateFormat.format(new Date(iso)) : empty

const cidrError = computed(() =>
  Object.entries(form.errors.value)
    .filter(([key]) => key === 'cidrs' || key.startsWith('cidrs.'))
    .map(([, message]) => message)
    .join(' '),
)
const otherErrors = computed(() =>
  Object.entries(form.errors.value)
    .filter(([key]) => !RENDERED.includes(key) && key !== 'cidrs' && !key.startsWith('cidrs.'))
    .map(([key, message]) => `${key}: ${message}`),
)

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    tokens.value = (await call(client.GET('/tokens'), { toast: false })).data.items
  } catch (e) {
    loadError.value = isApiError(e) ? (e.detail ?? e.title) : t('tokens.loadFailed')
  } finally {
    loading.value = false
  }
}
onMounted(load)

function clearSecret() {
  secret.value = ''
  secretName.value = ''
  copyStatus.value = ''
}
watch(secretOpen, (open) => {
  if (!open) clearSecret()
})
onBeforeUnmount(clearSecret)

function parseCidrs(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((c) => c.trim())
    .filter(Boolean)
}

async function submit() {
  if (busy.value) return
  formError.value = ''
  form.clear()
  if (scopes.value.length === 0) {
    form.errors.value = { scopes: t('tokens.create.scopesRequired') }
    return
  }
  let expiresAt: string | undefined
  if (expires.value) {
    const date = new Date(expires.value)
    if (Number.isNaN(date.getTime())) {
      form.errors.value = { expires_at: t('tokens.create.expiresInvalid') }
      return
    }
    expiresAt = date.toISOString()
  }
  busy.value = true
  try {
    const cidrs = parseCidrs(cidrText.value)
    const res = await call(
      client.POST('/tokens', {
        body: {
          name: name.value,
          scopes: scopes.value,
          ...(cidrs.length ? { cidrs } : {}),
          ...(expiresAt ? { expires_at: expiresAt } : {}),
        },
      }),
      { toast: false },
    )
    secret.value = res.data.token
    secretName.value = res.data.name
    secretOpen.value = true
    name.value = ''
    scopes.value = []
    cidrText.value = ''
    expires.value = ''
    await load()
  } catch (e) {
    if (!form.apply(e)) {
      formError.value = isApiError(e) ? (e.detail ?? e.title) : t('common.errors.unknown')
    }
  } finally {
    busy.value = false
  }
}

async function copySecret() {
  try {
    await navigator.clipboard.writeText(secret.value)
    copyStatus.value = t('tokens.secret.copied')
  } catch {
    copyStatus.value = t('tokens.secret.copyFailed')
  }
}

function askRevoke(token: Token) {
  pendingRevoke.value = token
  revokeError.value = ''
  revokeOpen.value = true
}

async function confirmRevoke() {
  const token = pendingRevoke.value
  if (!token) return
  revokeBusy.value = true
  revokeError.value = ''
  try {
    await call(client.DELETE('/tokens/{id}', { params: { path: { id: token.id } } }), {
      toast: false,
    })
    toasts.success(t('tokens.revoke.done', { name: token.name }))
    revokeOpen.value = false
    await load()
  } catch (e) {
    revokeError.value = isApiError(e) ? (e.detail ?? e.title) : t('common.errors.unknown')
  } finally {
    revokeBusy.value = false
  }
}

const isOwn = (token: Token) => token.user_id === session.me?.id
</script>

<template>
  <SkPageHeader :title="t('tokens.title')" :description="t('tokens.description')" />

  <div class="flex flex-col gap-10">
    <p class="text-sk-muted">
      <i class="ti ti-info-circle" aria-hidden="true" />
      {{ t('tokens.sessionNote') }}
    </p>

    <section :aria-label="t('tokens.caption')" class="flex flex-col gap-3">
      <p v-if="loading" role="status">{{ t('tokens.loading') }}</p>
      <div
        v-else-if="loadError"
        role="alert"
        class="flex flex-col items-start gap-2 rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
      >
        <p>
          <i class="ti ti-alert-circle" aria-hidden="true" />
          {{ t('tokens.loadFailed') }} {{ loadError }}
        </p>
        <Button :label="t('common.actions.retry')" @click="load" />
      </div>
      <SkEmptyState
        v-else-if="tokens.length === 0"
        icon="ti ti-key"
        :title="t('tokens.emptyTitle')"
        :description="t('tokens.emptyDescription')"
      />
      <div
        v-else
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('tokens.caption')"
      >
        <table class="w-full text-left text-sm">
          <caption class="sr-only">
            {{
              t('tokens.caption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('tokens.columns.name') }}</th>
              <th v-if="showOwner" scope="col" class="p-2">{{ t('tokens.columns.owner') }}</th>
              <th scope="col" class="p-2">{{ t('tokens.columns.scopes') }}</th>
              <th scope="col" class="p-2">{{ t('tokens.columns.cidrs') }}</th>
              <th scope="col" class="p-2">{{ t('tokens.columns.expires') }}</th>
              <th scope="col" class="p-2">{{ t('tokens.columns.lastUsed') }}</th>
              <th scope="col" class="p-2">{{ t('tokens.columns.created') }}</th>
              <th scope="col" class="p-2">{{ t('tokens.columns.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="token in tokens"
              :key="token.id"
              class="border-b border-sk-border align-top"
              :data-testid="`token-${token.id}`"
            >
              <th scope="row" class="p-2 font-medium">{{ token.name }}</th>
              <td v-if="showOwner" class="p-2 font-mono">
                {{ token.user_id }}
                <span v-if="isOwn(token)" class="font-sans text-sk-muted">{{
                  t('tokens.you')
                }}</span>
              </td>
              <td class="p-2">
                {{ token.scopes.map((s) => t(`tokens.scopes.${s}`)).join(', ') }}
              </td>
              <td class="p-2">
                {{ token.cidrs.length ? token.cidrs.join(', ') : t('tokens.anyNetwork') }}
              </td>
              <td class="p-2">{{ fmt(token.expires_at, t('tokens.noExpiry')) }}</td>
              <td class="p-2">{{ fmt(token.last_used_at, t('tokens.neverUsed')) }}</td>
              <td class="p-2">{{ fmt(token.created_at, '') }}</td>
              <td class="p-2">
                <Button
                  outlined
                  severity="danger"
                  size="small"
                  :label="t('tokens.revoke.action')"
                  :aria-label="t('tokens.revoke.actionLabel', { name: token.name })"
                  @click="askRevoke(token)"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section aria-labelledby="token-create-heading" class="flex max-w-xl flex-col gap-4">
      <h2 id="token-create-heading" class="text-lg font-semibold">
        {{ t('tokens.create.heading') }}
      </h2>
      <form class="flex flex-col gap-4" novalidate @submit.prevent="submit">
        <p
          v-if="formError || otherErrors.length"
          role="alert"
          class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
        >
          <i class="ti ti-alert-circle" aria-hidden="true" />
          {{ t('tokens.create.formError') }} {{ formError }}
          <span v-for="m in otherErrors" :key="m" class="block">{{ m }}</span>
        </p>
        <SkFormField
          :label="t('tokens.create.name')"
          :help="t('tokens.create.nameHelp')"
          :error="form.errorFor('name')"
          required
        >
          <template #default="{ attrs, invalid }">
            <InputText
              v-bind="attrs"
              v-model="name"
              :invalid="invalid"
              name="name"
              autocomplete="off"
              maxlength="64"
              fluid
              @update:model-value="form.clear('name')"
            />
          </template>
        </SkFormField>
        <fieldset
          class="flex flex-col gap-2"
          :aria-describedby="form.errorFor('scopes') ? 'token-scopes-error' : undefined"
          :aria-invalid="form.errorFor('scopes') ? 'true' : undefined"
        >
          <legend class="text-sm font-medium">
            {{ t('tokens.create.scopes') }}
            <span aria-hidden="true" class="text-sk-danger"> *</span>
            <span class="sr-only"> ({{ t('common.required') }})</span>
          </legend>
          <div v-for="scope in SCOPES" :key="scope" class="flex items-start gap-2">
            <input
              :id="`scope-${scope}`"
              v-model="scopes"
              type="checkbox"
              name="scopes"
              :value="scope"
              :aria-describedby="`scope-${scope}-help`"
              class="mt-1 size-5"
              @change="form.clear('scopes')"
            />
            <label :for="`scope-${scope}`" class="flex flex-col">
              <span class="font-medium">{{ t(`tokens.scopes.${scope}`) }}</span>
              <span :id="`scope-${scope}-help`" class="text-sm text-sk-muted">
                {{ t(`tokens.scopeHelp.${scope}`) }}
              </span>
            </label>
          </div>
          <p id="token-scopes-error" aria-live="polite" class="text-sm text-sk-danger">
            <template v-if="form.errorFor('scopes')">
              <i class="ti ti-alert-circle" aria-hidden="true" />
              {{ form.errorFor('scopes') }}
            </template>
          </p>
        </fieldset>
        <SkFormField
          :label="t('tokens.create.cidrs')"
          :help="t('tokens.create.cidrsHelp')"
          :error="cidrError || undefined"
        >
          <template #default="{ attrs, invalid }">
            <textarea
              v-bind="attrs"
              v-model="cidrText"
              name="cidrs"
              rows="3"
              spellcheck="false"
              autocomplete="off"
              :aria-invalid="invalid ? 'true' : undefined"
              class="w-full rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2 font-mono text-sm text-sk-text"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('tokens.create.expires')"
          :help="t('tokens.create.expiresHelp')"
          :error="form.errorFor('expires_at')"
        >
          <template #default="{ attrs, invalid }">
            <input
              v-bind="attrs"
              v-model="expires"
              type="datetime-local"
              name="expires_at"
              :aria-invalid="invalid ? 'true' : undefined"
              class="rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2 text-sk-text"
              @input="form.clear('expires_at')"
            />
          </template>
        </SkFormField>
        <div>
          <Button
            type="submit"
            :label="busy ? t('tokens.create.submitting') : t('tokens.create.submit')"
            :loading="busy"
          />
        </div>
      </form>
    </section>
  </div>

  <SkConfirmDialog
    v-model:open="secretOpen"
    :title="t('tokens.secret.title')"
    :confirm-label="t('tokens.secret.done')"
    :cancel-label="t('tokens.secret.close')"
    @confirm="secretOpen = false"
  >
    <template v-if="secret">
      <p
        role="alert"
        class="rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
      >
        <i class="ti ti-alert-triangle" aria-hidden="true" />
        {{ t('tokens.secret.warning') }}
      </p>
      <p class="text-sm font-medium" data-testid="secret-label">
        {{ t('tokens.secret.label', { name: secretName }) }}
      </p>
      <code
        class="block break-all rounded-sk border border-sk-border-strong bg-sk-surface-muted p-3 select-all"
        data-testid="secret-value"
        v-text="secret"
      />
      <div class="flex flex-col items-start gap-2">
        <Button type="button" outlined :label="t('tokens.secret.copy')" @click="copySecret" />
        <p role="status" class="text-sm">{{ copyStatus }}</p>
      </div>
    </template>
  </SkConfirmDialog>

  <SkConfirmDialog
    v-model:open="revokeOpen"
    danger
    :busy="revokeBusy"
    :title="t('tokens.revoke.title', { name: pendingRevoke?.name ?? '' })"
    :message="t('tokens.revoke.message')"
    :confirm-label="t('tokens.revoke.confirm')"
    @confirm="confirmRevoke"
  >
    <p v-if="revokeError" role="alert" class="text-sk-danger">
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ revokeError }}
    </p>
  </SkConfirmDialog>
</template>
