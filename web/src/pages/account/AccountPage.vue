<script setup lang="ts">
import Button from 'openvue/button'
import InputText from 'openvue/inputtext'
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import { useFormErrors } from '@/api/fieldErrors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { useToastStore } from '@/stores/toasts'

type Session = components['schemas']['Session']

const MIN_PASSWORD = 12

const { t } = useI18n()
const { client, call } = useApi()
const toasts = useToastStore()

const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const saving = ref(false)
const formError = ref('')
const form = useFormErrors({ known: ['current_password', 'new_password', 'confirm'] })

const sessions = ref<Session[]>([])
const sessionsLoading = ref(true)
const sessionsError = ref('')

const pendingRevoke = ref<Session>()
const revokeOpen = ref(false)
const revokeBusy = ref(false)

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const fmt = (iso: string) => dateFormat.format(new Date(iso))

async function loadSessions() {
  sessionsLoading.value = true
  sessionsError.value = ''
  try {
    sessions.value = (await call(client.GET('/auth/sessions'), { toast: false })).data.items
  } catch (e) {
    sessionsError.value = isApiError(e) ? (e.detail ?? e.title) : t('account.sessions.loadFailed')
  } finally {
    sessionsLoading.value = false
  }
}
onMounted(loadSessions)

async function changePassword() {
  if (saving.value) return
  formError.value = ''
  form.clear()
  if (newPassword.value.length < MIN_PASSWORD) {
    form.errors.value = { new_password: t('account.password.tooShort') }
    return
  }
  if (newPassword.value !== confirmPassword.value) {
    form.errors.value = { confirm: t('account.password.mismatch') }
    return
  }
  saving.value = true
  try {
    await call(
      client.POST('/auth/password', {
        body: { current_password: currentPassword.value, new_password: newPassword.value },
      }),
      { toast: false },
    )
    currentPassword.value = ''
    newPassword.value = ''
    confirmPassword.value = ''
    toasts.success(t('account.password.done'))
    await loadSessions()
  } catch (e) {
    if (!form.apply(e)) {
      formError.value = isApiError(e) ? (e.detail ?? e.title) : t('common.errors.unknown')
    }
  } finally {
    saving.value = false
  }
}

function askRevoke(session: Session) {
  pendingRevoke.value = session
  revokeOpen.value = true
}

async function confirmRevoke() {
  const session = pendingRevoke.value
  if (!session) return
  revokeBusy.value = true
  try {
    await call(client.DELETE('/auth/sessions/{id}', { params: { path: { id: session.id } } }), {
      toast: false,
    })
    toasts.success(t('account.sessions.revoked'))
    revokeOpen.value = false
    await loadSessions()
  } catch (e) {
    revokeOpen.value = false
    if (isApiError(e)) toasts.error(e)
    else toasts.error(t('common.errors.unknown'))
  } finally {
    revokeBusy.value = false
  }
}
</script>

<template>
  <SkPageHeader :title="t('account.title')" :description="t('account.description')" />

  <div class="flex flex-col gap-10">
    <section class="flex max-w-xl flex-col gap-4" aria-labelledby="account-password-heading">
      <h2 id="account-password-heading" class="text-lg font-semibold">
        {{ t('account.password.heading') }}
      </h2>
      <p class="text-sk-muted">{{ t('account.password.intro') }}</p>

      <form novalidate class="flex flex-col gap-4" @submit.prevent="changePassword">
        <div
          v-if="formError"
          role="alert"
          class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
        >
          {{ formError }}
        </div>
        <SkFormField
          :label="t('account.password.current')"
          :error="form.errorFor('current_password')"
          required
        >
          <template #default="{ attrs, invalid }">
            <InputText
              v-bind="attrs"
              v-model="currentPassword"
              type="password"
              name="current_password"
              autocomplete="current-password"
              :invalid="invalid"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('account.password.next')"
          :help="t('account.password.nextHelp')"
          :error="form.errorFor('new_password')"
          required
        >
          <template #default="{ attrs, invalid }">
            <InputText
              v-bind="attrs"
              v-model="newPassword"
              type="password"
              name="new_password"
              autocomplete="new-password"
              :invalid="invalid"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('account.password.confirm')"
          :error="form.errorFor('confirm')"
          required
        >
          <template #default="{ attrs, invalid }">
            <InputText
              v-bind="attrs"
              v-model="confirmPassword"
              type="password"
              name="confirm"
              autocomplete="new-password"
              :invalid="invalid"
            />
          </template>
        </SkFormField>
        <div>
          <Button
            type="submit"
            :label="saving ? t('account.password.saving') : t('account.password.submit')"
            :disabled="saving"
          />
        </div>
      </form>
    </section>

    <section class="flex flex-col gap-3" aria-labelledby="account-sessions-heading">
      <h2 id="account-sessions-heading" class="text-lg font-semibold">
        {{ t('account.sessions.heading') }}
      </h2>
      <p class="text-sk-muted">{{ t('account.sessions.intro') }}</p>

      <p v-if="sessionsLoading" role="status">{{ t('account.sessions.loading') }}</p>
      <div
        v-else-if="sessionsError"
        role="alert"
        class="flex flex-col items-start gap-2 rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
      >
        <p>{{ sessionsError }}</p>
        <Button :label="t('common.actions.retry')" @click="loadSessions" />
      </div>
      <div
        v-else
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('account.sessions.caption')"
      >
        <table class="w-full text-left text-sm">
          <caption class="sr-only">
            {{
              t('account.sessions.caption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('account.sessions.columns.started') }}</th>
              <th scope="col" class="p-2">{{ t('account.sessions.columns.lastActive') }}</th>
              <th scope="col" class="p-2">{{ t('account.sessions.columns.expires') }}</th>
              <th scope="col" class="p-2">{{ t('account.sessions.columns.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="session in sessions"
              :key="session.id"
              class="border-b border-sk-border align-top"
              :data-testid="session.current ? 'session-current' : 'session-other'"
            >
              <td class="p-2">{{ fmt(session.created_at) }}</td>
              <td class="p-2">{{ fmt(session.last_seen_at) }}</td>
              <td class="p-2">{{ fmt(session.expires_at) }}</td>
              <td class="p-2">
                <span v-if="session.current" class="text-sk-muted">
                  {{ t('account.sessions.current') }}
                </span>
                <Button v-else :label="t('account.sessions.revoke')" @click="askRevoke(session)" />
              </td>
            </tr>
            <tr v-if="sessions.length <= 1">
              <td colspan="4" class="p-2 text-sk-muted">{{ t('account.sessions.empty') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <SkConfirmDialog
    v-model:open="revokeOpen"
    danger
    :busy="revokeBusy"
    :title="t('account.sessions.revokeTitle')"
    :message="t('account.sessions.revokeMessage')"
    :confirm-label="t('account.sessions.revokeConfirm')"
    @confirm="confirmRevoke"
  />
</template>
