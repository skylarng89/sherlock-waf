<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import SkFormField from '@/components/SkFormField.vue'
import ListControl from '@/pages/sites/controls/ListControl.vue'
import NumberControl from '@/pages/sites/controls/NumberControl.vue'
import { controlClass } from '@/pages/sites/controls/classes'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { hasStoredSecret, type FieldSpec, type Model, type Settings } from './spec'

const props = defineProps<{
  spec: FieldSpec[]
  /** The stored (masked) settings being edited; tells which secrets already have a value. */
  stored?: Settings
  errors?: Record<string, string>
  /** `integrations.options.<group>` holds the option labels of select fields. */
  optionGroup: string
  /** Site ids offered by `site` fields. */
  sites?: string[]
}>()
const model = defineModel<Model>({ required: true })

const { t, te } = useI18n()

function set(path: string, value: Model[string]) {
  model.value = { ...model.value, [path]: value }
}
function label(f: FieldSpec) {
  return t(`integrations.fields.${f.label}`)
}
function help(f: FieldSpec) {
  return f.help ? t(`integrations.fields.${f.label}Help`) : undefined
}
function optionLabel(value: string) {
  const key = `integrations.options.${props.optionGroup}.${value}`
  return te(key) ? t(key) : value
}
function str(path: string): string {
  const v = model.value[path]
  return typeof v === 'string' ? v : ''
}
</script>

<template>
  <div class="flex flex-col gap-4">
    <template v-for="f in spec" :key="f.path">
      <div v-if="f.kind === 'bool'" class="flex flex-col gap-1">
        <SwitchControl
          :model-value="model[f.path] === true"
          :label="label(f)"
          :aria-describedby="f.help ? `${f.path}-help` : undefined"
          @update:model-value="set(f.path, $event)"
        />
        <p v-if="f.help" :id="`${f.path}-help`" class="text-sm text-sk-muted">{{ help(f) }}</p>
      </div>
      <SkFormField
        v-else
        :label="label(f)"
        :help="help(f)"
        :error="errors?.[f.path]"
        :required="f.required"
      >
        <template #default="{ attrs, invalid }">
          <input
            v-if="f.kind === 'secret'"
            v-bind="attrs"
            type="password"
            autocomplete="new-password"
            :value="str(f.path)"
            :placeholder="hasStoredSecret(stored, f.path) ? t('integrations.unchanged') : ''"
            :class="controlClass"
            @input="set(f.path, ($event.target as HTMLInputElement).value)"
          />
          <SelectControl
            v-else-if="f.kind === 'site'"
            v-bind="attrs"
            :model-value="str(f.path)"
            :empty-label="t('integrations.fields.allSites')"
            :options="(sites ?? []).map((s) => ({ value: s, label: s }))"
            @update:model-value="set(f.path, $event ?? '')"
          />
          <SelectControl
            v-else-if="f.kind === 'select'"
            v-bind="attrs"
            :model-value="str(f.path)"
            :options="(f.options ?? []).map((o) => ({ value: o, label: optionLabel(o) }))"
            @update:model-value="set(f.path, $event ?? '')"
          />
          <NumberControl
            v-else-if="f.kind === 'number'"
            v-bind="attrs"
            :model-value="typeof model[f.path] === 'number' ? (model[f.path] as number) : undefined"
            @update:model-value="set(f.path, $event)"
          />
          <ListControl
            v-else-if="f.kind === 'list'"
            v-bind="attrs"
            :model-value="Array.isArray(model[f.path]) ? (model[f.path] as string[]) : []"
            @update:model-value="set(f.path, $event)"
          />
          <textarea
            v-else-if="f.kind === 'textarea' || f.kind === 'headers'"
            v-bind="attrs"
            :value="str(f.path)"
            rows="4"
            autocapitalize="off"
            spellcheck="false"
            :class="[controlClass, 'font-mono']"
            @input="set(f.path, ($event.target as HTMLTextAreaElement).value)"
          />
          <TextControl
            v-else
            v-bind="attrs"
            :model-value="str(f.path)"
            :mono="f.mono"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="set(f.path, $event)"
          />
        </template>
      </SkFormField>
    </template>
  </div>
</template>
