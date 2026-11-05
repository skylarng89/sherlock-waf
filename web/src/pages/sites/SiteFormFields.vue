<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { components } from '@/api/schema'
import SkFormField from '@/components/SkFormField.vue'
import ListControl from './controls/ListControl.vue'
import NumberControl from './controls/NumberControl.vue'
import SelectControl from './controls/SelectControl.vue'
import SwitchControl from './controls/SwitchControl.vue'
import TextControl from './controls/TextControl.vue'
import type { Policy } from './lib/layers'
import type { SiteDraft } from './lib/siteDraft'
import PolicyForm from './PolicyForm.vue'

type Certificate = components['schemas']['Certificate']

const props = defineProps<{
  /** Create mode lets the id be typed; it is immutable afterwards. */
  isNew: boolean
  readonly: boolean
  certificates: Certificate[]
  blockPages: string[]
  defaults: Policy
  errorFor: (path: string) => string | undefined
  clearError: (path: string) => void
}>()

const site = defineModel<SiteDraft>({ required: true })
const { t } = useI18n()

const certOptions = computed(() =>
  props.certificates.map((c) => ({
    value: c.id,
    label: `${c.name} (${c.hosts.join(', ')})`,
  })),
)

function opts<T extends string>(group: string, values: readonly T[]) {
  return values.map((value) => ({ value, label: t(`sites.options.${group}.${value}`) }))
}

const layers = computed(() => [{ label: t('sites.source.global'), policy: props.defaults }])
</script>

<template>
  <div class="flex flex-col gap-8">
    <fieldset class="flex flex-col gap-4" :disabled="readonly">
      <legend class="mb-2 text-lg font-semibold">{{ t('sites.sections.general') }}</legend>
      <SkFormField
        :label="t('sites.fields.id.label')"
        :help="isNew ? t('sites.fields.id.help') : t('sites.fields.id.immutable')"
        :error="errorFor('id')"
        required
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="site.id"
            mono
            :disabled="!isNew || readonly"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('id')"
          />
        </template>
      </SkFormField>
      <SkFormField :label="t('sites.fields.name.label')" :error="errorFor('name')">
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="site.name"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('name')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('sites.fields.hosts.label')"
        :help="t('sites.fields.hosts.help')"
        :error="errorFor('hosts')"
        required
      >
        <template #default="{ attrs, invalid }">
          <ListControl
            v-bind="attrs"
            v-model="site.hosts"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('hosts')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('sites.fields.pathPrefix.label')"
        :help="t('sites.fields.pathPrefix.help')"
        :error="errorFor('path_prefix')"
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="site.path_prefix"
            mono
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('path_prefix')"
          />
        </template>
      </SkFormField>
    </fieldset>

    <fieldset class="flex flex-col gap-4" :disabled="readonly">
      <legend class="mb-2 text-lg font-semibold">{{ t('sites.sections.tls') }}</legend>
      <SkFormField
        :label="t('sites.fields.tlsMode.label')"
        :help="t('sites.fields.tlsMode.help')"
        :error="errorFor('tls.mode')"
      >
        <template #default="{ attrs, invalid }">
          <SelectControl
            v-bind="attrs"
            v-model="site.tls.mode"
            :options="opts('tlsMode', ['acme', 'file', 'none'] as const)"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('tls.mode')"
          />
        </template>
      </SkFormField>
      <SkFormField
        v-if="site.tls.mode === 'file'"
        :label="t('sites.fields.certId.label')"
        :help="t('sites.fields.certId.help')"
        :error="errorFor('tls.cert_id')"
      >
        <template #default="{ attrs, invalid }">
          <SelectControl
            v-bind="attrs"
            v-model="site.tls.cert_id"
            :options="certOptions"
            :empty-label="t('sites.fields.certId.choose')"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('tls.cert_id')"
          />
        </template>
      </SkFormField>
      <p v-if="site.tls.mode === 'none'" class="text-sk-warning">
        <i class="ti ti-alert-triangle" aria-hidden="true" />
        {{ t('sites.fields.tlsMode.noneWarning') }}
      </p>
      <SkFormField :label="t('sites.fields.minVersion.label')" :error="errorFor('tls.min_version')">
        <template #default="{ attrs, invalid }">
          <SelectControl
            v-bind="attrs"
            v-model="site.tls.min_version"
            :options="[
              { value: '1.2', label: 'TLS 1.2' },
              { value: '1.3', label: 'TLS 1.3' },
            ]"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('tls.min_version')"
          />
        </template>
      </SkFormField>
      <SkFormField :label="t('sites.fields.hsts.label')" :error="errorFor('tls.hsts.enabled')">
        <template #default="{ attrs }">
          <SwitchControl
            v-bind="attrs"
            v-model="site.tls.hsts.enabled"
            :label="t('sites.fields.hsts.enabled')"
          />
        </template>
      </SkFormField>
      <template v-if="site.tls.hsts.enabled">
        <SkFormField
          :label="t('sites.fields.hstsMaxAge.label')"
          :help="t('sites.fields.hstsMaxAge.help')"
          :error="errorFor('tls.hsts.max_age')"
        >
          <template #default="{ attrs, invalid }">
            <NumberControl
              v-bind="attrs"
              v-model="site.tls.hsts.max_age"
              min="0"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="clearError('tls.hsts.max_age')"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('sites.fields.hstsSubdomains.label')"
          :error="errorFor('tls.hsts.include_subdomains')"
        >
          <template #default="{ attrs }">
            <SwitchControl
              v-bind="attrs"
              v-model="site.tls.hsts.include_subdomains"
              :label="t('sites.fields.hstsSubdomains.enabled')"
            />
          </template>
        </SkFormField>
      </template>
    </fieldset>

    <fieldset class="flex flex-col gap-4" :disabled="readonly">
      <legend class="mb-2 text-lg font-semibold">{{ t('sites.sections.upstreams') }}</legend>
      <SkFormField
        :label="t('sites.fields.targets.label')"
        :help="t('sites.fields.targets.help')"
        :error="errorFor('upstreams.targets')"
        required
      >
        <template #default="{ attrs, invalid }">
          <ListControl
            v-bind="attrs"
            v-model="site.upstreams.targets"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('upstreams.targets')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('sites.fields.lbPolicy.label')"
        :error="errorFor('upstreams.lb_policy')"
      >
        <template #default="{ attrs, invalid }">
          <SelectControl
            v-bind="attrs"
            v-model="site.upstreams.lb_policy"
            :options="opts('lbPolicy', ['round_robin', 'least_conn', 'ip_hash'] as const)"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('upstreams.lb_policy')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('sites.fields.healthPath.label')"
        :help="t('sites.fields.healthPath.help')"
        :error="errorFor('upstreams.health_check.path')"
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="site.upstreams.health_check.path"
            mono
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('upstreams.health_check.path')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('sites.fields.healthInterval.label')"
        :help="t('sites.fields.duration')"
        :error="errorFor('upstreams.health_check.interval')"
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="site.upstreams.health_check.interval"
            mono
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('upstreams.health_check.interval')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('sites.fields.healthTimeout.label')"
        :help="t('sites.fields.duration')"
        :error="errorFor('upstreams.health_check.timeout')"
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="site.upstreams.health_check.timeout"
            mono
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('upstreams.health_check.timeout')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('sites.fields.upstreamTls.label')"
        :help="t('sites.fields.upstreamTls.help')"
        :error="errorFor('upstreams.tls.enabled')"
      >
        <template #default="{ attrs }">
          <SwitchControl
            v-bind="attrs"
            v-model="site.upstreams.tls.enabled"
            :label="t('sites.fields.upstreamTls.enabled')"
          />
        </template>
      </SkFormField>
      <template v-if="site.upstreams.tls.enabled">
        <SkFormField
          :label="t('sites.fields.skipVerify.label')"
          :help="t('sites.fields.skipVerify.help')"
          :error="errorFor('upstreams.tls.insecure_skip_verify')"
        >
          <template #default="{ attrs }">
            <SwitchControl
              v-bind="attrs"
              v-model="site.upstreams.tls.insecure_skip_verify"
              :label="t('sites.fields.skipVerify.enabled')"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('sites.fields.clientCert.label')"
          :help="t('sites.fields.clientCert.help')"
          :error="errorFor('upstreams.tls.client_cert_id')"
        >
          <template #default="{ attrs, invalid }">
            <SelectControl
              v-bind="attrs"
              v-model="site.upstreams.tls.client_cert_id"
              :options="certOptions"
              :empty-label="t('common.none')"
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="clearError('upstreams.tls.client_cert_id')"
            />
          </template>
        </SkFormField>
      </template>
      <SkFormField
        v-for="k in ['dial', 'read', 'write'] as const"
        :key="k"
        :label="t(`sites.fields.timeout.${k}`)"
        :help="t('sites.fields.duration')"
        :error="errorFor(`upstreams.timeouts.${k}`)"
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="site.upstreams.timeouts[k]"
            mono
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError(`upstreams.timeouts.${k}`)"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('sites.fields.httpVersion.label')"
        :error="errorFor('upstreams.http_version')"
      >
        <template #default="{ attrs, invalid }">
          <SelectControl
            v-bind="attrs"
            v-model="site.upstreams.http_version"
            :options="[
              { value: '1.1', label: t('sites.options.httpVersion.http11') },
              { value: '2', label: t('sites.options.httpVersion.http2') },
              { value: 'h2c', label: t('sites.options.httpVersion.h2c') },
            ]"
            :empty-label="t('sites.options.httpVersion.auto')"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="clearError('upstreams.http_version')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('sites.fields.websockets.label')"
        :help="t('sites.fields.websockets.help')"
        :error="errorFor('upstreams.websockets')"
      >
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="site.upstreams.websockets === false ? 'deny' : 'allow'"
            :options="opts('websockets', ['allow', 'deny'] as const)"
            @update:model-value="site.upstreams.websockets = $event !== 'deny'"
          />
        </template>
      </SkFormField>
    </fieldset>

    <fieldset class="flex flex-col gap-4">
      <legend class="mb-2 text-lg font-semibold">{{ t('sites.sections.policy') }}</legend>
      <p class="text-sk-muted">{{ t('sites.sections.policyHelp') }}</p>
      <PolicyForm
        v-model="site.policy"
        :layers="layers"
        :block-pages="blockPages"
        :disabled="readonly"
        :error-for="(p) => errorFor(`policy.${p}`)"
      />
    </fieldset>
  </div>
</template>
