<script setup lang="ts">
import Button from 'openvue/button'
import { onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { ApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { useSessionStore } from '@/stores/session'
import { CONTINUE_PATH } from './constants'
import WizardSteps from './WizardSteps.vue'

const { t } = useI18n()
const router = useRouter()
const session = useSessionStore()
const { client, call } = useApi()

const token = ref('')
const username = ref('')
const password = ref('')
const confirm = ref('')
const busy = ref(false)
const closed = ref(false)
const throttledFor = ref(0)
const signInFailed = ref(false)
const form = useFormErrors({ known: ['setup_token', 'username', 'password', 'confirm'] })
let timer: ReturnType<typeof setInterval> | undefined

function startCountdown(seconds: number) {
  if (timer) clearInterval(timer)
  throttledFor.value = seconds
  timer = setInterval(() => {
    throttledFor.value -= 1
    if (throttledFor.value <= 0 && timer) clearInterval(timer)
  }, 1000)
}
onBeforeUnmount(() => timer && clearInterval(timer))

function validate(): boolean {
  const errors: Record<string, string> = {}
  if (!token.value.trim()) errors.setup_token = t('setup.admin.errors.tokenRequired')
  if (!/^[A-Za-z0-9._-]{3,64}$/.test(username.value)) {
    errors.username = t('setup.admin.errors.username')
  }
  if (password.value.length < 12) errors.password = t('setup.admin.errors.passwordShort')
  else if (confirm.value !== password.value) errors.confirm = t('setup.admin.errors.mismatch')
  form.errors.value = errors
  return Object.keys(errors).length === 0
}

async function submit() {
  if (busy.value || throttledFor.value > 0) return
  form.clear()
  signInFailed.value = false
  if (!validate()) return
  busy.value = true
  try {
    await call(
      client.POST('/setup/admin', {
        body: {
          setup_token: token.value.trim(),
          username: username.value,
          password: password.value,
        },
      }),
      { toast: false },
    )
  } catch (e) {
    busy.value = false
    if (!(e instanceof ApiError)) throw e
    if (e.kind === 'forbidden') {
      form.errors.value = { setup_token: t('setup.admin.errors.wrongToken') }
    } else if (e.kind === 'rate_limited') startCountdown(e.retryAfter ?? 60)
    else if (e.kind === 'conflict') {
      closed.value = true
      session.markSetupComplete()
    } else if (!form.apply(e)) form.errors.value = { setup_token: e.detail ?? e.title }
    return
  }

  token.value = ''
  session.markSetupComplete()
  try {
    // Reuse the normal sign-in; MFA enrolment follows and then returns to the wizard.
    const outcome = await session.login(username.value, password.value)
    password.value = ''
    confirm.value = ''
    await router.replace(
      outcome === 'ok'
        ? { path: CONTINUE_PATH }
        : {
            name: outcome === 'mfa_enrol_required' ? 'login-enrol' : 'login-mfa',
            query: { redirect: CONTINUE_PATH },
          },
    )
  } catch {
    signInFailed.value = true
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader :title="t('setup.title')" :description="t('setup.description')" />
  <WizardSteps :current="1" />

  <div
    v-if="closed"
    role="alert"
    class="rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
  >
    <p>{{ t('setup.admin.closed') }}</p>
    <RouterLink :to="{ name: 'login' }" class="underline">{{
      t('setup.admin.toLogin')
    }}</RouterLink>
  </div>

  <div
    v-else-if="signInFailed"
    role="alert"
    class="rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
  >
    <p>{{ t('setup.admin.signInFailed') }}</p>
    <RouterLink :to="{ name: 'login', query: { redirect: CONTINUE_PATH } }" class="underline">
      {{ t('setup.admin.toLogin') }}
    </RouterLink>
  </div>

  <form v-else class="flex flex-col gap-4" novalidate @submit.prevent="submit">
    <h2 class="text-lg font-semibold">{{ t('setup.admin.heading') }}</h2>
    <p
      v-if="throttledFor > 0"
      role="alert"
      class="rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
    >
      <i class="ti ti-hourglass" aria-hidden="true" />
      {{ t('setup.admin.throttled', { seconds: throttledFor }) }}
    </p>
    <SkFormField
      :label="t('setup.admin.token')"
      :help="t('setup.admin.tokenHelp')"
      :error="form.errorFor('setup_token')"
      required
    >
      <template #default="{ attrs, invalid }">
        <input
          v-bind="attrs"
          v-model="token"
          type="password"
          name="setup_token"
          autocomplete="off"
          spellcheck="false"
          :aria-invalid="invalid ? 'true' : undefined"
          class="w-full rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2 font-mono"
          @input="form.clear('setup_token')"
        />
      </template>
    </SkFormField>
    <SkFormField
      :label="t('setup.admin.username')"
      :help="t('setup.admin.usernameHelp')"
      :error="form.errorFor('username')"
      required
    >
      <template #default="{ attrs, invalid }">
        <TextControl
          v-bind="attrs"
          v-model="username"
          name="username"
          autocomplete="username"
          :aria-invalid="invalid ? 'true' : undefined"
          @update:model-value="form.clear('username')"
        />
      </template>
    </SkFormField>
    <SkFormField
      :label="t('setup.admin.password')"
      :help="t('setup.admin.passwordHelp')"
      :error="form.errorFor('password')"
      required
    >
      <template #default="{ attrs, invalid }">
        <input
          v-bind="attrs"
          v-model="password"
          type="password"
          name="password"
          autocomplete="new-password"
          :aria-invalid="invalid ? 'true' : undefined"
          class="w-full rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2"
          @input="form.clear('password')"
        />
      </template>
    </SkFormField>
    <SkFormField :label="t('setup.admin.confirm')" :error="form.errorFor('confirm')" required>
      <template #default="{ attrs, invalid }">
        <input
          v-bind="attrs"
          v-model="confirm"
          type="password"
          name="confirm"
          autocomplete="new-password"
          :aria-invalid="invalid ? 'true' : undefined"
          class="w-full rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2"
          @input="form.clear('confirm')"
        />
      </template>
    </SkFormField>
    <p v-if="form.unmatched.value.length" role="alert" class="text-sk-danger">
      {{ form.unmatched.value.join(' ') }}
    </p>
    <div>
      <Button
        type="submit"
        :label="busy ? t('setup.admin.submitting') : t('setup.admin.submit')"
        :loading="busy"
        :disabled="busy || throttledFor > 0"
      />
    </div>
  </form>
</template>
