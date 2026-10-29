<script setup lang="ts">
import Button from 'openvue/button'
import InputText from 'openvue/inputtext'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormErrors } from '@/api/fieldErrors'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import { useToastStore } from '@/stores/toasts'

const emit = defineEmits<{ uploaded: [] }>()

const { t } = useI18n()
const { client, call } = useApi()
const toasts = useToastStore()
const form = useFormErrors({ known: ['name', 'certificate_pem', 'private_key_pem'] })

const name = ref('')
const certificatePem = ref('')
// Held only in component state and wiped after every attempt.
const privateKeyPem = ref('')
const busy = ref(false)
const formError = ref('')
const certFile = ref<HTMLInputElement>()
const keyFile = ref<HTMLInputElement>()

const areaClass =
  'w-full rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2 font-mono text-sm text-sk-text'

async function readFile(event: Event, target: 'certificate' | 'key') {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    const text = await file.text()
    if (target === 'certificate') {
      certificatePem.value = text
      form.clear('certificate_pem')
    } else {
      privateKeyPem.value = text
      form.clear('private_key_pem')
    }
  } catch {
    formError.value = t('certificates.upload.fileReadFailed')
  } finally {
    input.value = ''
  }
}

function wipeKey() {
  privateKeyPem.value = ''
  if (keyFile.value) keyFile.value.value = ''
}

async function submit() {
  if (busy.value) return
  busy.value = true
  formError.value = ''
  form.clear()
  try {
    await call(
      client.POST('/certificates', {
        body: {
          name: name.value,
          certificate_pem: certificatePem.value,
          private_key_pem: privateKeyPem.value,
        },
      }),
      { toast: false },
    )
    toasts.success(t('certificates.upload.stored', { name: name.value }))
    name.value = ''
    certificatePem.value = ''
    if (certFile.value) certFile.value.value = ''
    emit('uploaded')
  } catch (e) {
    if (!form.apply(e)) {
      formError.value = e instanceof Error ? e.message : t('certificates.upload.formError')
    }
  } finally {
    wipeKey()
    busy.value = false
  }
}
</script>

<template>
  <section class="flex flex-col gap-4" aria-labelledby="cert-upload-heading">
    <h2 id="cert-upload-heading" class="text-lg font-semibold">
      {{ t('certificates.upload.heading') }}
    </h2>
    <p class="text-sk-muted">{{ t('certificates.upload.intro') }}</p>
    <form class="flex max-w-3xl flex-col gap-4" novalidate @submit.prevent="submit">
      <p
        v-if="formError || form.unmatched.value.length"
        role="alert"
        class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
      >
        <i class="ti ti-alert-circle" aria-hidden="true" />
        {{ t('certificates.upload.formError') }}
        {{ formError }}
        <span v-for="m in form.unmatched.value" :key="m" class="block">{{ m }}</span>
      </p>
      <SkFormField
        :label="t('certificates.upload.name')"
        :help="t('certificates.upload.nameHelp')"
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
      <SkFormField
        :label="t('certificates.upload.certificate')"
        :help="t('certificates.upload.certificateHelp')"
        :error="form.errorFor('certificate_pem')"
        required
      >
        <template #default="{ attrs, invalid }">
          <textarea
            v-bind="attrs"
            v-model="certificatePem"
            name="certificate_pem"
            rows="6"
            spellcheck="false"
            autocomplete="off"
            :class="areaClass"
            :aria-invalid="invalid ? 'true' : undefined"
            @input="form.clear('certificate_pem')"
          />
        </template>
      </SkFormField>
      <SkFormField :label="t('certificates.upload.certificateFile')">
        <template #default="{ attrs }">
          <input
            :id="attrs.id"
            ref="certFile"
            type="file"
            accept=".pem,.crt,.cer,.txt"
            @change="readFile($event, 'certificate')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('certificates.upload.key')"
        :help="t('certificates.upload.keyHelp')"
        :error="form.errorFor('private_key_pem')"
        required
      >
        <template #default="{ attrs, invalid }">
          <textarea
            v-bind="attrs"
            v-model="privateKeyPem"
            name="private_key_pem"
            rows="6"
            spellcheck="false"
            autocomplete="off"
            autocapitalize="off"
            :class="[areaClass, '[-webkit-text-security:disc]']"
            :aria-invalid="invalid ? 'true' : undefined"
            @input="form.clear('private_key_pem')"
          />
        </template>
      </SkFormField>
      <SkFormField :label="t('certificates.upload.keyFile')">
        <template #default="{ attrs }">
          <input
            :id="attrs.id"
            ref="keyFile"
            type="file"
            accept=".pem,.key,.txt"
            @change="readFile($event, 'key')"
          />
        </template>
      </SkFormField>
      <div>
        <Button
          type="submit"
          :label="busy ? t('certificates.upload.submitting') : t('certificates.upload.submit')"
          :loading="busy"
        />
      </div>
    </form>
  </section>
</template>
