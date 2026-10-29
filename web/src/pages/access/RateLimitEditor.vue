<script setup lang="ts">
import Button from 'openvue/button'
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import SkFormField from '@/components/SkFormField.vue'
import ListControl from '@/pages/sites/controls/ListControl.vue'
import NumberControl from '@/pages/sites/controls/NumberControl.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import {
  DURATION_PATTERN,
  HEADER_PATTERN,
  HTTP_METHODS,
  MAX_RATE_LIMIT_VALUE,
  NAME_PATTERN,
  type RateLimit,
} from './policy'

const props = defineProps<{
  /** The item being edited; undefined starts a new one. */
  item?: RateLimit
  /** Names already used at this level (excluding the item itself). */
  taken: string[]
  /** Name of an inherited item this one would replace, if any, to say so. */
  overrides?: (name: string) => string | undefined
}>()
const emit = defineEmits<{ apply: [item: RateLimit]; cancel: [] }>()

const { t } = useI18n()

const headerKey = props.item?.key?.startsWith('header:')
const draft = reactive({
  name: props.item?.name ?? '',
  paths: [...(props.item?.match?.paths ?? [])],
  methods: [...(props.item?.match?.methods ?? [])],
  keyKind: headerKey ? 'header' : 'ip',
  header: headerKey ? (props.item?.key ?? '').slice('header:'.length) : '',
  limit: props.item?.limit as number | undefined,
  window: props.item?.window ?? '1m',
  action: props.item?.action ?? 'block',
})
const errors = ref<Record<string, string>>({})

const overridden = computed(() => props.overrides?.(draft.name.trim()))

function validate(): Record<string, string> {
  const out: Record<string, string> = {}
  const name = draft.name.trim()
  if (!NAME_PATTERN.test(name)) out.name = t('access.rateLimits.errors.name')
  else if (props.taken.includes(name)) out.name = t('access.rateLimits.errors.duplicate')
  if (
    draft.limit === undefined ||
    !Number.isInteger(draft.limit) ||
    draft.limit < 1 ||
    draft.limit > MAX_RATE_LIMIT_VALUE
  ) {
    out.limit = t('access.rateLimits.errors.limit', { max: MAX_RATE_LIMIT_VALUE })
  }
  if (!DURATION_PATTERN.test(draft.window)) out.window = t('access.rateLimits.errors.window')
  if (draft.keyKind === 'header' && !HEADER_PATTERN.test(draft.header)) {
    out.key = t('access.rateLimits.errors.header')
  }
  const bad = draft.paths.findIndex((p) => !p.startsWith('/'))
  if (bad >= 0) out.paths = t('access.rateLimits.errors.path', { line: bad + 1 })
  return out
}

function apply() {
  errors.value = validate()
  if (Object.keys(errors.value).length) return
  const match = {
    ...(draft.paths.length ? { paths: [...draft.paths] } : {}),
    ...(draft.methods.length ? { methods: [...draft.methods] } : {}),
  }
  emit('apply', {
    name: draft.name.trim(),
    ...(Object.keys(match).length ? { match } : {}),
    key: draft.keyKind === 'header' ? `header:${draft.header}` : 'ip',
    limit: draft.limit ?? 0,
    window: draft.window,
    action: draft.action,
  })
}
</script>

<template>
  <fieldset
    class="flex flex-col gap-4 rounded-sk border border-sk-border-strong p-4"
    data-testid="rate-limit-editor"
    @keydown.enter.prevent="apply"
  >
    <legend class="px-1 text-lg font-semibold">
      {{
        item
          ? t('access.rateLimits.editTitle', { name: item.name })
          : t('access.rateLimits.newTitle')
      }}
    </legend>

    <SkFormField
      :label="t('access.rateLimits.fields.name')"
      :help="t('access.rateLimits.fields.nameHelp')"
      :error="errors.name"
      required
    >
      <template #default="{ attrs, invalid }">
        <TextControl
          v-bind="attrs"
          v-model="draft.name"
          mono
          :aria-invalid="invalid ? 'true' : undefined"
        />
      </template>
    </SkFormField>
    <p
      v-if="overridden"
      role="status"
      class="rounded-sk border border-sk-info bg-sk-info-bg p-2 text-sm text-sk-info"
    >
      <i class="ti ti-replace" aria-hidden="true" />
      {{ t('access.rateLimits.willOverride', { source: overridden }) }}
    </p>

    <SkFormField
      :label="t('access.rateLimits.fields.paths')"
      :help="t('access.rateLimits.fields.pathsHelp')"
      :error="errors.paths"
    >
      <template #default="{ attrs, invalid }">
        <ListControl
          v-bind="attrs"
          v-model="draft.paths"
          :aria-invalid="invalid ? 'true' : undefined"
        />
      </template>
    </SkFormField>

    <fieldset class="flex flex-col gap-1">
      <legend class="text-sm font-medium">{{ t('access.rateLimits.fields.methods') }}</legend>
      <p class="text-sm text-sk-muted">{{ t('access.rateLimits.fields.methodsHelp') }}</p>
      <div class="flex flex-wrap gap-4">
        <label v-for="m in HTTP_METHODS" :key="m" class="flex items-center gap-2">
          <input
            v-model="draft.methods"
            type="checkbox"
            :value="m"
            class="size-4 accent-[var(--sk-accent)]"
          />
          {{ m }}
        </label>
      </div>
    </fieldset>

    <div class="flex flex-wrap gap-4">
      <SkFormField :label="t('access.rateLimits.fields.keyKind')">
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="draft.keyKind"
            :options="[
              { value: 'ip', label: t('access.rateLimits.keys.ip') },
              { value: 'header', label: t('access.rateLimits.keys.header') },
            ]"
            @update:model-value="draft.keyKind = $event ?? 'ip'"
          />
        </template>
      </SkFormField>
      <SkFormField
        v-if="draft.keyKind === 'header'"
        :label="t('access.rateLimits.fields.header')"
        :error="errors.key"
        required
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="draft.header"
            mono
            :aria-invalid="invalid ? 'true' : undefined"
          />
        </template>
      </SkFormField>
    </div>

    <div class="flex flex-wrap gap-4">
      <SkFormField :label="t('access.rateLimits.fields.limit')" :error="errors.limit" required>
        <template #default="{ attrs, invalid }">
          <NumberControl
            v-bind="attrs"
            v-model="draft.limit"
            :min="1"
            :aria-invalid="invalid ? 'true' : undefined"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('access.rateLimits.fields.window')"
        :help="t('access.rateLimits.fields.windowHelp')"
        :error="errors.window"
        required
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="draft.window"
            mono
            :aria-invalid="invalid ? 'true' : undefined"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('access.rateLimits.fields.action')"
        :help="t('access.rateLimits.challengeNote')"
      >
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="draft.action"
            :options="
              (['block', 'challenge', 'log'] as const).map((a) => ({
                value: a,
                label: t(`access.actions.${a}`),
              }))
            "
            @update:model-value="draft.action = $event ?? 'block'"
          />
        </template>
      </SkFormField>
    </div>

    <div class="flex gap-2">
      <Button type="button" :label="t('access.rateLimits.apply')" @click="apply" />
      <Button
        type="button"
        severity="secondary"
        :label="t('common.actions.cancel')"
        @click="emit('cancel')"
      />
    </div>
  </fieldset>
</template>
