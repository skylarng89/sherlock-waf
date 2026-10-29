<script setup lang="ts">
import InputText from 'openvue/inputtext'
import Button from 'openvue/button'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
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

const code = ref('')
const error = ref<string>()
const busy = ref(false)
const redirect = safeRedirect(route.query.redirect)

async function submit() {
  if (busy.value) return
  error.value = undefined
  if (!/^\d{6}$/.test(code.value)) {
    error.value = t('auth.mfa.wrongCode')
    return
  }
  busy.value = true
  try {
    await session.verifyMfa(code.value)
    await router.replace(redirect ?? '/')
  } catch (e) {
    if (!(e instanceof ApiError)) throw e
    if (e.kind === 'unauthenticated' || e.kind === 'validation') {
      code.value = ''
      error.value = t('auth.mfa.wrongCode')
      // The 5-minute partial session may have lapsed: then the code was never the problem.
      if ((await session.fetchMe()) !== 'partial') {
        await router.replace({ name: 'login', query: { expired: '1' } })
      }
    } else toasts.error(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader :title="t('auth.mfa.title')" :description="t('auth.mfa.description')" />
  <form class="flex flex-col gap-4" novalidate @submit.prevent="submit">
    <SkFormField :label="t('auth.mfa.code')" :help="t('auth.mfa.help')" :error="error" required>
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
    <Button type="submit" :label="t('auth.mfa.submit')" :loading="busy" />
  </form>
  <p class="mt-4 flex flex-col gap-1 text-sm">
    <RouterLink :to="{ name: 'login-enrol', query: route.query }" class="text-sk-accent underline">
      {{ t('auth.mfa.enrolInstead') }}
    </RouterLink>
    <RouterLink :to="{ name: 'login' }" class="text-sk-accent underline">
      {{ t('auth.mfa.backToLogin') }}
    </RouterLink>
  </p>
</template>
