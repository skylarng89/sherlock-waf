<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import SkFormField from '@/components/SkFormField.vue'
import { controlClass } from '@/pages/sites/controls/classes'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { HASH_PASSWORD_CLI_COMING_SOON, HASH_PASSWORD_COMMAND, type AclPolicy } from './policy'

type Gate = NonNullable<AclPolicy['password_gate']>

const props = defineProps<{
  modelValue: Gate | undefined
  attrs: Record<string, unknown>
  /** Messages for the sub-fields, keyed `username` / `password_hash`. */
  errors?: { username?: string; password_hash?: string }
  disabled?: boolean
}>()
const emit = defineEmits<{ update: [value: Gate] }>()

const { t } = useI18n()

// The server never returns the stored hash; it sends this marker and keeps the stored hash
// whenever the marker (or nothing) comes back.
const REDACTED = '<redacted>'
const hadStoredHash = ref(props.modelValue?.password_hash === REDACTED)
const hashIsSet = computed(() => props.modelValue?.password_hash === REDACTED)

function onHashInput(value: string) {
  set({ password_hash: value === '' && hadStoredHash.value ? REDACTED : value })
}

function set(patch: Gate) {
  emit('update', { enabled: true, ...props.modelValue, ...patch })
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <SwitchControl
      v-bind="attrs"
      :model-value="modelValue?.enabled ?? true"
      :label="t('access.acl.passwordGate.enabled')"
      :disabled="disabled"
      @update:model-value="set({ enabled: $event })"
    />
    <SkFormField :label="t('access.acl.passwordGate.username')" :error="errors?.username">
      <template #default="{ attrs: a }">
        <TextControl
          v-bind="a"
          :model-value="modelValue?.username"
          :disabled="disabled"
          @update:model-value="set({ username: $event })"
        />
      </template>
    </SkFormField>
    <SkFormField
      :label="t('access.acl.passwordGate.hash')"
      :help="t('access.acl.passwordGate.hashHelp')"
      :error="errors?.password_hash"
    >
      <template #default="{ attrs: a }">
        <input
          v-bind="a"
          type="password"
          :value="hashIsSet ? '' : (modelValue?.password_hash ?? '')"
          :class="[controlClass, 'font-mono']"
          autocomplete="off"
          spellcheck="false"
          :placeholder="hashIsSet ? t('access.acl.passwordGate.hashSetPlaceholder') : undefined"
          :disabled="disabled"
          @input="onHashInput(($event.target as HTMLInputElement).value)"
        />
        <p v-if="hashIsSet" class="mt-1 text-sm text-sk-muted" data-testid="hash-set">
          <i class="ti ti-lock-check" aria-hidden="true" />
          {{ t('access.acl.passwordGate.hashSet') }}
        </p>
      </template>
    </SkFormField>
    <details class="rounded-sk border border-sk-border p-3">
      <summary class="cursor-pointer font-medium">
        {{ t('access.acl.passwordGate.helpTitle') }}
        <span
          v-if="HASH_PASSWORD_CLI_COMING_SOON"
          class="ml-2 inline-flex items-center gap-1 rounded-full bg-sk-warning-bg px-2 py-0.5 text-xs text-sk-warning"
        >
          <i class="ti ti-clock" aria-hidden="true" />
          {{ t('access.acl.passwordGate.comingSoon') }}
        </span>
      </summary>
      <p class="mt-2 text-sk-muted">{{ t('access.acl.passwordGate.helpBody') }}</p>
      <pre class="mt-2 overflow-x-auto rounded-sk bg-sk-surface-muted p-2 font-mono text-sm">{{
        HASH_PASSWORD_COMMAND
      }}</pre>
      <p v-if="HASH_PASSWORD_CLI_COMING_SOON" class="mt-2 text-sm text-sk-warning">
        {{ t('access.acl.passwordGate.notYet') }}
      </p>
      <p class="mt-2 text-sm text-sk-muted">{{ t('access.acl.passwordGate.noBrowserHashing') }}</p>
    </details>
  </div>
</template>
