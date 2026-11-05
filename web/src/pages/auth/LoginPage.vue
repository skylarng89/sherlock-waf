<script setup lang="ts">
import InputText from 'openvue/inputtext'
import Button from 'openvue/button'
import { computed, onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { useFormErrors } from '@/api/fieldErrors'
import { ApiError } from '@/api/errors'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { safeRedirect } from '@/router/guard'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const toasts = useToastStore()
const form = useFormErrors({ known: ['username', 'password'] })

const username = ref('')
const password = ref('')
const busy = ref(false)
const badCredentials = ref(false)
const throttledFor = ref(0)
const announcedSeconds = ref(0)
let timer: ReturnType<typeof setInterval> | undefined

const expired = computed(() => route.query.expired === '1')
const throttled = computed(() => throttledFor.value > 0)

function startCountdown(seconds: number) {
  stopCountdown()
  announcedSeconds.value = seconds
  throttledFor.value = seconds
  timer = setInterval(() => {
    throttledFor.value -= 1
    if (throttledFor.value <= 0) stopCountdown()
  }, 1000)
}

function stopCountdown() {
  if (timer) clearInterval(timer)
  timer = undefined
  throttledFor.value = Math.max(0, throttledFor.value)
}
onBeforeUnmount(stopCountdown)

async function submit() {
  if (busy.value || throttled.value) return
  busy.value = true
  badCredentials.value = false
  form.clear()
  try {
    const outcome = await session.login(username.value, password.value)
    password.value = ''
    const redirect = safeRedirect(route.query.redirect)
    if (outcome === 'ok') await router.replace(redirect ?? '/')
    else
      await router.replace({
        name: outcome === 'mfa_enrol_required' ? 'login-enrol' : 'login-mfa',
        query: redirect ? { redirect } : {},
      })
  } catch (e) {
    if (!(e instanceof ApiError)) throw e
    if (e.kind === 'unauthenticated') badCredentials.value = true
    else if (e.kind === 'rate_limited') startCountdown(e.retryAfter ?? 60)
    else if (!form.apply(e)) toasts.error(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader :title="t('auth.login.title')" :description="t('auth.login.description')" />

  <p
    v-if="expired"
    role="status"
    class="mb-4 rounded-sk border border-sk-info bg-sk-info-bg p-3 text-sk-info"
  >
    <i class="ti ti-clock-exclamation" aria-hidden="true" />
    {{ t('auth.login.expired') }}
  </p>

  <div>
    <p
      v-if="badCredentials"
      role="alert"
      class="mb-4 rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
    >
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ t('auth.login.badCredentials') }}
    </p>
    <div
      v-else-if="announcedSeconds > 0"
      class="mb-4 rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
    >
      <!-- One static announcement; the ticking number is hidden from assistive tech. -->
      <p v-if="throttled" role="alert">
        <i class="ti ti-hourglass" aria-hidden="true" />
        {{ t('auth.login.throttled', { seconds: announcedSeconds }) }}
        <span aria-hidden="true" data-testid="countdown">({{ throttledFor }})</span>
      </p>
      <p v-else role="status">{{ t('auth.login.throttledReady') }}</p>
    </div>
  </div>

  <form class="flex flex-col gap-4" novalidate @submit.prevent="submit">
    <SkFormField :label="t('auth.login.username')" :error="form.errorFor('username')" required>
      <template #default="{ attrs, invalid }">
        <InputText
          v-bind="attrs"
          v-model="username"
          :invalid="invalid"
          name="username"
          autocomplete="username"
          autocapitalize="off"
          spellcheck="false"
          fluid
        />
      </template>
    </SkFormField>
    <SkFormField :label="t('auth.login.password')" :error="form.errorFor('password')" required>
      <template #default="{ attrs, invalid }">
        <InputText
          v-bind="attrs"
          v-model="password"
          :invalid="invalid"
          type="password"
          name="password"
          autocomplete="current-password"
          fluid
        />
      </template>
    </SkFormField>
    <Button
      type="submit"
      :label="busy ? t('auth.login.submitting') : t('auth.login.submit')"
      :loading="busy"
      :disabled="throttled"
    />
  </form>
</template>
