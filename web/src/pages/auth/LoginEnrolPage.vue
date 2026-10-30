<script setup lang="ts">
import InputText from 'openvue/inputtext'
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { ApiError } from '@/api/errors'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { safeRedirect } from '@/router/guard'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import QrCode from './QrCode.vue'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const toasts = useToastStore()

// Held in memory only: the secret is shown once and must not reach web storage.
const enrolment = ref<{ secret: string; otpauth_uri: string }>()
const loadFailed = ref(false)
const code = ref('')
const error = ref<string>()
const busy = ref(false)
const redirect = safeRedirect(route.query.redirect)

const groupedSecret = computed(() => enrolment.value?.secret.match(/.{1,4}/g)?.join(' ') ?? '')

async function expiredOrFail(e: unknown): Promise<boolean> {
  if (
    e instanceof ApiError &&
    e.kind === 'unauthenticated' &&
    (await session.fetchMe()) !== 'partial'
  ) {
    await router.replace({ name: 'login', query: { expired: '1' } })
    return true
  }
  return false
}

onMounted(async () => {
  try {
    enrolment.value = await session.startEnrolment()
  } catch (e) {
    if (await expiredOrFail(e)) return
    loadFailed.value = true
    if (e instanceof ApiError) toasts.error(e)
  }
})

async function submit() {
  if (busy.value) return
  error.value = undefined
  if (!/^\d{6}$/.test(code.value)) {
    error.value = t('auth.enrol.wrongCode')
    return
  }
  busy.value = true
  try {
    await session.confirmEnrolment(code.value)
    await router.replace(redirect ?? '/')
  } catch (e) {
    if (!(e instanceof ApiError)) throw e
    if (await expiredOrFail(e)) return
    if (e.kind === 'unauthenticated' || e.kind === 'validation') {
      code.value = ''
      error.value = t('auth.enrol.wrongCode')
    } else toasts.error(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader :title="t('auth.enrol.title')" :description="t('auth.enrol.description')" />

  <p
    v-if="loadFailed"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    {{ t('auth.enrol.failed') }}
    <RouterLink :to="{ name: 'login' }" class="underline">{{
      t('auth.mfa.backToLogin')
    }}</RouterLink>
  </p>
  <p v-else-if="!enrolment" role="status" class="text-sk-muted">{{ t('auth.enrol.loading') }}</p>

  <div v-else class="flex flex-col gap-6">
    <div class="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
      <QrCode :value="enrolment.otpauth_uri" :label="t('auth.enrol.qrLabel')" />
      <div class="min-w-0">
        <h2 class="text-sm font-medium">{{ t('auth.enrol.secretLabel') }}</h2>
        <p class="mt-1 font-mono text-lg break-all select-all" data-testid="secret">
          {{ groupedSecret }}
        </p>
        <p class="mt-1 text-sm text-sk-muted">{{ t('auth.enrol.secretHelp') }}</p>
      </div>
    </div>

    <form class="flex flex-col gap-4" novalidate @submit.prevent="submit">
      <SkFormField :label="t('auth.enrol.code')" :error="error" required>
        <template #default="{ attrs, invalid }">
          <InputText
            v-bind="attrs"
            v-model="code"
            :invalid="invalid"
            name="code"
            inputmode="numeric"
            autocomplete="one-time-code"
            pattern="[0-9]*"
            maxlength="6"
            fluid
          />
        </template>
      </SkFormField>
      <Button type="submit" :label="t('auth.enrol.submit')" :loading="busy" />
    </form>
  </div>
</template>
