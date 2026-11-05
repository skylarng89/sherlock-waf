<script setup lang="ts">
import Button from 'openvue/button'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import { useFormErrors } from '@/api/fieldErrors'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import NumberControl from '@/pages/sites/controls/NumberControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { useToastStore } from '@/stores/toasts'

const MIN_SECONDS = 60
const MAX_SECONDS = 2_592_000
const PRESETS = [
  { id: '15m', seconds: 900 },
  { id: '1h', seconds: 3_600 },
  { id: '24h', seconds: 86_400 },
  { id: '7d', seconds: 604_800 },
] as const

defineProps<{ sites: string[] }>()
const emit = defineEmits<{ created: [] }>()

const { t } = useI18n()
const { client, call } = useApi()
const toasts = useToastStore()

const ip = ref('')
const site = ref<string>()
const preset = ref<string>('1h')
const customHours = ref<number>()
const reason = ref('')
const busy = ref(false)
// 409: the server refuses to ban the address this browser is connecting from.
const selfBan = ref(false)
const form = useFormErrors({ known: ['ip', 'site_id', 'duration_seconds', 'reason'] })

function seconds(): number | undefined {
  if (preset.value !== 'custom') return PRESETS.find((p) => p.id === preset.value)?.seconds
  return customHours.value === undefined ? undefined : Math.round(customHours.value * 3_600)
}

function onIpInput() {
  selfBan.value = false
  form.clear('ip')
}

async function submit() {
  form.clear()
  selfBan.value = false
  const errors: Record<string, string> = {}
  const duration = seconds()
  if (!ip.value.trim()) errors.ip = t('bans.errors.ipRequired')
  if (duration === undefined || duration < MIN_SECONDS || duration > MAX_SECONDS) {
    errors.duration_seconds = t('bans.errors.duration')
  }
  form.errors.value = errors
  if (Object.keys(errors).length || duration === undefined) return

  busy.value = true
  try {
    await call(
      client.POST('/bans', {
        body: {
          ip: ip.value.trim(),
          ...(site.value ? { site_id: site.value } : {}),
          duration_seconds: duration,
          ...(reason.value.trim() ? { reason: reason.value.trim() } : {}),
        },
      }),
      { toast: false },
    )
    toasts.success(t('bans.created', { ip: ip.value.trim() }))
    ip.value = ''
    reason.value = ''
    emit('created')
  } catch (e) {
    if (isApiError(e) && e.kind === 'conflict') selfBan.value = true
    else if (isApiError(e) && e.status === 400 && !e.hasFieldErrors) {
      form.errors.value = { ip: e.detail ?? e.title }
    } else if (!form.apply(e)) toasts.error(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="rounded-sk border border-sk-border p-4" aria-labelledby="create-ban-title">
    <h2 id="create-ban-title" class="mb-3 text-lg font-semibold">{{ t('bans.create.title') }}</h2>
    <form class="flex flex-col gap-4" novalidate @submit.prevent="submit">
      <p
        v-if="selfBan"
        role="alert"
        class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
      >
        <i class="ti ti-alert-octagon" aria-hidden="true" />
        {{ t('bans.errors.selfBan') }}
      </p>
      <div class="flex flex-wrap gap-4">
        <div class="min-w-48 flex-1">
          <SkFormField
            :label="t('bans.create.ip')"
            :help="t('bans.create.ipHelp')"
            :error="form.errorFor('ip')"
            required
          >
            <template #default="{ attrs, invalid }">
              <TextControl
                v-bind="attrs"
                v-model="ip"
                mono
                :aria-invalid="invalid ? 'true' : undefined"
                @update:model-value="onIpInput"
              />
            </template>
          </SkFormField>
        </div>
        <SkFormField :label="t('bans.create.site')" :error="form.errorFor('site_id')">
          <template #default="{ attrs }">
            <SelectControl
              v-bind="attrs"
              v-model="site"
              :empty-label="t('bans.create.allSites')"
              :options="sites.map((s) => ({ value: s, label: s }))"
            />
          </template>
        </SkFormField>
      </div>

      <fieldset class="flex flex-col gap-2">
        <legend class="text-sm font-medium">{{ t('bans.create.duration') }}</legend>
        <div class="flex flex-wrap items-center gap-4">
          <label v-for="p in PRESETS" :key="p.id" class="flex items-center gap-2">
            <input
              v-model="preset"
              type="radio"
              name="ban-duration"
              :value="p.id"
              class="size-4 accent-[var(--sk-accent)]"
            />
            {{ t(`bans.create.presets.${p.id}`) }}
          </label>
          <label class="flex items-center gap-2">
            <input
              v-model="preset"
              type="radio"
              name="ban-duration"
              value="custom"
              class="size-4 accent-[var(--sk-accent)]"
            />
            {{ t('bans.create.presets.custom') }}
          </label>
        </div>
        <div v-if="preset === 'custom'" class="max-w-xs">
          <SkFormField :label="t('bans.create.customHours')" :help="t('bans.create.customHelp')">
            <template #default="{ attrs }">
              <NumberControl v-bind="attrs" v-model="customHours" :min="1" />
            </template>
          </SkFormField>
        </div>
        <p id="duration-error" aria-live="polite" class="text-sm text-sk-danger">
          <template v-if="form.errorFor('duration_seconds')">
            <i class="ti ti-alert-circle" aria-hidden="true" />
            {{ form.errorFor('duration_seconds') }}
          </template>
        </p>
      </fieldset>

      <SkFormField
        :label="t('bans.create.reason')"
        :help="t('bans.create.reasonHelp')"
        :error="form.errorFor('reason')"
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="reason"
            :aria-invalid="invalid ? 'true' : undefined"
          />
        </template>
      </SkFormField>

      <div>
        <Button type="submit" :label="t('bans.create.submit')" :loading="busy" :disabled="busy" />
      </div>
    </form>
  </section>
</template>
