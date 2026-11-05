<script setup lang="ts">
import Button from 'openvue/button'
import InputText from 'openvue/inputtext'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import { useFormErrors } from '@/api/fieldErrors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SkStatusBadge from '@/components/SkStatusBadge.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'

type User = components['schemas']['User']
type Role = User['role']
type ActionKind = 'role' | 'disable' | 'enable' | 'password' | 'mfa' | 'delete'

const MIN_PASSWORD = 12

const { t } = useI18n()
const { client, call } = useApi()
const session = useSessionStore()
const toasts = useToastStore()

const users = ref<User[]>([])
const loading = ref(true)
const loadError = ref('')

const selectClass =
  'w-full rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2 text-sk-text'

// Create form
const createForm = useFormErrors({ known: ['username', 'password', 'role'] })
const newUsername = ref('')
const newPassword = ref('')
const newRole = ref<Role>('viewer')
const creating = ref(false)
const createError = ref('')

// Row action dialog (one dialog for every action keeps focus handling in one place)
const action = ref<{ kind: ActionKind; user: User }>()
const dialogOpen = ref(false)
const dialogBusy = ref(false)
const dialogError = ref('')
const dialogRole = ref<Role>('viewer')
const dialogPassword = ref('')
const dialogForm = useFormErrors({ known: ['password', 'role'] })

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    users.value = (await call(client.GET('/users'), { toast: false })).data.items
  } catch (e) {
    loadError.value = isApiError(e) ? (e.detail ?? e.title) : t('users.loadFailed')
  } finally {
    loading.value = false
  }
}
onMounted(load)

async function createUser() {
  if (creating.value) return
  createError.value = ''
  createForm.clear()
  if (newPassword.value.length < MIN_PASSWORD) {
    createForm.errors.value = { password: t('users.create.passwordTooShort') }
    return
  }
  creating.value = true
  const username = newUsername.value
  try {
    await call(
      client.POST('/users', {
        body: { username, password: newPassword.value, role: newRole.value },
      }),
      { toast: false },
    )
    toasts.success(t('users.create.created', { name: username }))
    newUsername.value = ''
    newRole.value = 'viewer'
    await load()
  } catch (e) {
    if (!createForm.apply(e)) {
      createError.value = isApiError(e) ? (e.detail ?? e.title) : t('common.errors.unknown')
    }
  } finally {
    newPassword.value = ''
    creating.value = false
  }
}

function open(kind: ActionKind, user: User) {
  action.value = { kind, user }
  dialogError.value = ''
  dialogPassword.value = ''
  dialogRole.value = user.role
  dialogForm.clear()
  dialogOpen.value = true
}

const dialogText = computed(() => {
  const a = action.value
  const name = a?.user.username ?? ''
  const key = a?.kind ?? 'role'
  const keys = {
    role: ['roleTitle', undefined, 'roleConfirm'],
    disable: ['disableTitle', 'disableMessage', 'disableConfirm'],
    enable: ['enableTitle', 'enableMessage', 'enableConfirm'],
    password: ['passwordTitle', undefined, 'passwordConfirm'],
    mfa: ['mfaTitle', 'mfaMessage', 'mfaConfirm'],
    delete: ['deleteTitle', 'deleteMessage', 'deleteConfirm'],
  } as const
  const [title, message, confirm] = keys[key]
  return {
    title: t(`users.dialog.${title}`, { name }),
    message: message ? t(`users.dialog.${message}`) : undefined,
    confirm: t(`users.dialog.${confirm}`),
  }
})

async function perform() {
  const a = action.value
  if (!a) return
  const id = a.user.id
  const path = { params: { path: { id } } }
  const doneKeys = {
    role: 'roleDone',
    disable: 'disabledDone',
    enable: 'enabledDone',
    password: 'passwordDone',
    mfa: 'mfaDone',
    delete: 'deleteDone',
  } as const
  dialogBusy.value = true
  dialogError.value = ''
  dialogForm.clear()
  try {
    if (a.kind === 'role') {
      await call(client.PATCH('/users/{id}', { ...path, body: { role: dialogRole.value } }), {
        toast: false,
      })
    } else if (a.kind === 'disable' || a.kind === 'enable') {
      await call(
        client.PATCH('/users/{id}', { ...path, body: { disabled: a.kind === 'disable' } }),
        { toast: false },
      )
    } else if (a.kind === 'password') {
      if (dialogPassword.value.length < MIN_PASSWORD) {
        dialogForm.errors.value = { password: t('users.create.passwordTooShort') }
        return
      }
      await call(
        client.PATCH('/users/{id}', { ...path, body: { password: dialogPassword.value } }),
        { toast: false },
      )
    } else if (a.kind === 'mfa') {
      await call(client.POST('/users/{id}/reset-mfa', path), { toast: false })
    } else {
      await call(client.DELETE('/users/{id}', path), { toast: false })
    }
    toasts.success(t(`users.dialog.${doneKeys[a.kind]}`, { name: a.user.username }))
    dialogOpen.value = false
    await load()
  } catch (e) {
    if (dialogForm.apply(e)) return
    if (isApiError(e) && e.kind === 'conflict') {
      dialogError.value = e.detail
        ? t('users.dialog.conflict', { detail: e.detail })
        : t('users.dialog.conflictFallback')
    } else {
      dialogError.value = isApiError(e) ? (e.detail ?? e.title) : t('common.errors.unknown')
    }
  } finally {
    dialogPassword.value = ''
    dialogBusy.value = false
  }
}

const isSelf = (u: User) => u.id === session.me?.id
const label = (kind: string, u: User) =>
  t('users.actions.forUser', { action: t(`users.actions.${kind}`), name: u.username })
</script>

<template>
  <SkPageHeader :title="t('users.title')" :description="t('users.description')" />

  <div class="flex flex-col gap-10">
    <section :aria-label="t('users.caption')" class="flex flex-col gap-3">
      <p v-if="loading" role="status">{{ t('users.loading') }}</p>
      <div
        v-else-if="loadError"
        role="alert"
        class="flex flex-col items-start gap-2 rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
      >
        <p>
          <i class="ti ti-alert-circle" aria-hidden="true" />
          {{ t('users.loadFailed') }} {{ loadError }}
        </p>
        <Button :label="t('common.actions.retry')" @click="load" />
      </div>
      <SkEmptyState
        v-else-if="users.length === 0"
        icon="ti ti-users"
        :title="t('users.emptyTitle')"
        :description="t('users.emptyDescription')"
      />
      <div
        v-else
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('users.caption')"
      >
        <table class="w-full text-left text-sm">
          <caption class="sr-only">
            {{
              t('users.caption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('users.columns.username') }}</th>
              <th scope="col" class="p-2">{{ t('users.columns.role') }}</th>
              <th scope="col" class="p-2">{{ t('users.columns.mfa') }}</th>
              <th scope="col" class="p-2">{{ t('users.columns.status') }}</th>
              <th scope="col" class="p-2">{{ t('users.columns.lastLogin') }}</th>
              <th scope="col" class="p-2">{{ t('users.columns.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="user in users"
              :key="user.id"
              class="border-b border-sk-border align-top"
              :data-testid="`user-${user.username}`"
            >
              <th scope="row" class="p-2 font-medium">
                {{ user.username }}
                <span v-if="isSelf(user)" class="font-normal text-sk-muted">{{
                  t('users.you')
                }}</span>
              </th>
              <td class="p-2">{{ t(`users.roles.${user.role}`) }}</td>
              <td class="p-2">
                <SkStatusBadge
                  :state="user.mfa_enabled ? 'ok' : 'warn'"
                  :label="user.mfa_enabled ? t('users.mfa.enabled') : t('users.mfa.notEnrolled')"
                />
              </td>
              <td class="p-2">
                <div class="flex flex-wrap gap-1">
                  <SkStatusBadge
                    v-if="user.disabled"
                    state="error"
                    :label="t('users.state.disabled')"
                  />
                  <SkStatusBadge v-if="user.locked" state="warn" :label="t('users.state.locked')" />
                  <SkStatusBadge
                    v-if="!user.disabled && !user.locked"
                    state="ok"
                    :label="t('users.state.active')"
                  />
                </div>
              </td>
              <td class="p-2">
                {{
                  user.last_login_at
                    ? dateFormat.format(new Date(user.last_login_at))
                    : t('users.neverSignedIn')
                }}
              </td>
              <td class="p-2">
                <div class="flex flex-wrap gap-1">
                  <Button
                    outlined
                    size="small"
                    :label="t('users.actions.changeRole')"
                    :aria-label="label('changeRole', user)"
                    @click="open('role', user)"
                  />
                  <Button
                    outlined
                    size="small"
                    :label="user.disabled ? t('users.actions.enable') : t('users.actions.disable')"
                    :aria-label="label(user.disabled ? 'enable' : 'disable', user)"
                    @click="open(user.disabled ? 'enable' : 'disable', user)"
                  />
                  <Button
                    outlined
                    size="small"
                    :label="t('users.actions.resetPassword')"
                    :aria-label="label('resetPassword', user)"
                    @click="open('password', user)"
                  />
                  <Button
                    outlined
                    size="small"
                    :label="t('users.actions.resetMfa')"
                    :aria-label="label('resetMfa', user)"
                    @click="open('mfa', user)"
                  />
                  <Button
                    outlined
                    severity="danger"
                    size="small"
                    :label="t('users.actions.delete')"
                    :aria-label="label('delete', user)"
                    @click="open('delete', user)"
                  />
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section aria-labelledby="user-create-heading" class="flex max-w-xl flex-col gap-4">
      <h2 id="user-create-heading" class="text-lg font-semibold">
        {{ t('users.create.heading') }}
      </h2>
      <form class="flex flex-col gap-4" novalidate @submit.prevent="createUser">
        <p
          v-if="createError || createForm.unmatched.value.length"
          role="alert"
          class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
        >
          <i class="ti ti-alert-circle" aria-hidden="true" />
          {{ t('users.create.formError') }} {{ createError }}
          <span v-for="m in createForm.unmatched.value" :key="m" class="block">{{ m }}</span>
        </p>
        <SkFormField
          :label="t('users.create.username')"
          :help="t('users.create.usernameHelp')"
          :error="createForm.errorFor('username')"
          required
        >
          <template #default="{ attrs, invalid }">
            <InputText
              v-bind="attrs"
              v-model="newUsername"
              :invalid="invalid"
              name="username"
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
              maxlength="64"
              fluid
              @update:model-value="createForm.clear('username')"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('users.create.password')"
          :help="t('users.create.passwordHelp')"
          :error="createForm.errorFor('password')"
          required
        >
          <template #default="{ attrs, invalid }">
            <InputText
              v-bind="attrs"
              v-model="newPassword"
              :invalid="invalid"
              type="password"
              name="password"
              autocomplete="new-password"
              fluid
              @update:model-value="createForm.clear('password')"
            />
          </template>
        </SkFormField>
        <SkFormField :label="t('users.create.role')" :error="createForm.errorFor('role')" required>
          <template #default="{ attrs }">
            <select v-bind="attrs" v-model="newRole" name="role" :class="selectClass">
              <option value="viewer">{{ t('users.roles.viewer') }}</option>
              <option value="admin">{{ t('users.roles.admin') }}</option>
            </select>
          </template>
        </SkFormField>
        <div>
          <Button
            type="submit"
            :label="creating ? t('users.create.submitting') : t('users.create.submit')"
            :loading="creating"
          />
        </div>
      </form>
    </section>
  </div>

  <SkConfirmDialog
    v-model:open="dialogOpen"
    :danger="action?.kind === 'delete' || action?.kind === 'disable'"
    :busy="dialogBusy"
    :title="dialogText.title"
    :message="dialogText.message"
    :confirm-label="dialogText.confirm"
    :confirm-text="action?.kind === 'delete' ? action.user.username : undefined"
    @confirm="perform"
  >
    <SkFormField
      v-if="action?.kind === 'role'"
      :label="t('users.dialog.roleLabel')"
      :error="dialogForm.errorFor('role')"
    >
      <template #default="{ attrs }">
        <select v-bind="attrs" v-model="dialogRole" name="dialog-role" :class="selectClass">
          <option value="viewer">{{ t('users.roles.viewer') }}</option>
          <option value="admin">{{ t('users.roles.admin') }}</option>
        </select>
      </template>
    </SkFormField>
    <SkFormField
      v-if="action?.kind === 'password'"
      :label="t('users.dialog.passwordLabel')"
      :help="t('users.dialog.passwordHelp')"
      :error="dialogForm.errorFor('password')"
      required
    >
      <template #default="{ attrs, invalid }">
        <InputText
          v-bind="attrs"
          v-model="dialogPassword"
          :invalid="invalid"
          type="password"
          name="dialog-password"
          autocomplete="new-password"
          fluid
          @update:model-value="dialogForm.clear('password')"
        />
      </template>
    </SkFormField>
    <p v-if="dialogError" role="alert" class="text-sk-danger">
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ dialogError }}
    </p>
  </SkConfirmDialog>
</template>
