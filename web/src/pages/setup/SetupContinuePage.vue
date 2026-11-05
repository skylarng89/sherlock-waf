<script setup lang="ts">
import Button from 'openvue/button'
import { computed, nextTick, onMounted, ref, useTemplateRef, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormErrors } from '@/api/fieldErrors'
import { isApiError } from '@/api/errors'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { SITE_ID_PATTERN, type Site } from '@/pages/sites/lib/siteDraft'
import { useToastStore } from '@/stores/toasts'
import { ADMIN_SITE_ID, DEFAULT_CONTROL_PLANE } from './constants'
import UpstreamTest from './UpstreamTest.vue'
import { useAddSite } from './useAddSite'
import WizardSteps from './WizardSteps.vue'

type Step = 2 | 3 | 4

const { t } = useI18n()
const toasts = useToastStore()
const { addSite } = useAddSite()

const step = ref<Step>(2)
const busy = ref(false)
const heading = useTemplateRef<HTMLElement>('heading')

// Step 2: optional admin hostname.
const adminHost = ref('')
const controlPlane = ref(DEFAULT_CONTROL_PLANE)
const adminForm = useFormErrors({
  known: ['hostname', 'address'],
  aliases: { hosts: 'hostname', 'upstreams.targets': 'address' },
})
const adminCreated = ref(false)

// Step 3: first site.
const siteName = ref('')
const siteId = ref('')
const idTouched = ref(false)
const siteHost = ref('')
const target = ref('')
const upstreamTls = ref(false)
const skipVerify = ref(false)
const tlsMode = ref<'acme' | 'none'>('acme')
const siteForm = useFormErrors({
  known: ['id', 'name', 'host', 'target', 'tls.mode'],
  aliases: { hosts: 'host', 'upstreams.targets': 'target' },
})
const siteCreated = ref(false)

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
}

function onIdInput() {
  idTouched.value = true
  siteForm.clear('id')
}

watch(siteName, (name) => {
  if (!idTouched.value) siteId.value = slug(name)
})

const lastSummary = computed(() => ({
  admin: adminCreated.value,
  site: siteCreated.value,
}))

// Move focus to the new step heading so keyboard and screen-reader users land in the right place.
watch(step, async () => {
  await nextTick()
  heading.value?.focus()
})
onMounted(() => heading.value?.focus())

async function createAdminSite() {
  adminForm.clear()
  const errors: Record<string, string> = {}
  if (!adminHost.value.trim()) errors.hostname = t('setup.hostname.errors.required')
  if (!controlPlane.value.trim()) errors.address = t('setup.hostname.errors.addressRequired')
  adminForm.errors.value = errors
  if (Object.keys(errors).length) return

  const site: Site = {
    id: ADMIN_SITE_ID,
    name: t('setup.hostname.siteName'),
    hosts: [adminHost.value.trim()],
    tls: { mode: 'acme' },
    // The hop to the control plane is local; its certificate is self-signed.
    upstreams: {
      targets: [controlPlane.value.trim()],
      tls: { enabled: true, insecure_skip_verify: true },
    },
    policy: { mode: 'detect' },
  }
  busy.value = true
  try {
    await addSite(site)
    adminCreated.value = true
    toasts.success(t('setup.hostname.created'))
    step.value = 3
  } catch (e) {
    if (isApiError(e) && e.kind === 'conflict') {
      toasts.info(t('setup.hostname.exists'))
      adminCreated.value = true
      step.value = 3
    } else if (!adminForm.apply(e)) {
      toasts.error(e)
    }
  } finally {
    busy.value = false
  }
}

async function createSite() {
  siteForm.clear()
  const errors: Record<string, string> = {}
  if (!SITE_ID_PATTERN.test(siteId.value)) errors.id = t('sites.errors.idPattern')
  if (!siteHost.value.trim()) errors.host = t('sites.errors.hostsRequired')
  if (!target.value.trim()) errors.target = t('sites.errors.targetsRequired')
  siteForm.errors.value = errors
  if (Object.keys(errors).length) return

  const site: Site = {
    id: siteId.value,
    name: siteName.value.trim() || undefined,
    hosts: [siteHost.value.trim()],
    tls: { mode: tlsMode.value },
    upstreams: {
      targets: [target.value.trim()],
      ...(upstreamTls.value
        ? { tls: { enabled: true, insecure_skip_verify: skipVerify.value } }
        : {}),
    },
    policy: { mode: 'detect' },
  }
  busy.value = true
  try {
    await addSite(site)
    siteCreated.value = true
    step.value = 4
  } catch (e) {
    if (isApiError(e) && e.kind === 'conflict') {
      siteForm.errors.value = { id: t('sites.errors.duplicate') }
    } else if (!siteForm.apply(e)) {
      toasts.error(e)
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader :title="t('setup.title')" :description="t('setup.continueDescription')" />
  <WizardSteps :current="step" />

  <section v-if="step === 2" aria-labelledby="step-heading">
    <h2 id="step-heading" ref="heading" tabindex="-1" class="mb-2 text-lg font-semibold">
      {{ t('setup.hostname.heading') }}
    </h2>
    <p class="mb-2 text-sk-muted">{{ t('setup.hostname.intro') }}</p>
    <ul class="mb-4 list-disc pl-6 text-sk-muted">
      <li>{{ t('setup.hostname.reqDns') }}</li>
      <li>{{ t('setup.hostname.reqPorts') }}</li>
    </ul>
    <form class="flex flex-col gap-4" novalidate @submit.prevent="createAdminSite">
      <SkFormField
        :label="t('setup.hostname.hostname')"
        :help="t('setup.hostname.hostnameHelp')"
        :error="adminForm.errorFor('hostname')"
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="adminHost"
            name="admin_hostname"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="adminForm.clear('hostname')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('setup.hostname.address')"
        :help="t('setup.hostname.addressHelp')"
        :error="adminForm.errorFor('address')"
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="controlPlane"
            name="control_plane"
            mono
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="adminForm.clear('address')"
          />
        </template>
      </SkFormField>
      <p v-if="adminForm.unmatched.value.length" role="alert" class="text-sk-danger">
        {{ adminForm.unmatched.value.join(' ') }}
      </p>
      <div class="flex gap-2">
        <Button
          type="submit"
          :label="t('setup.hostname.submit')"
          :loading="busy"
          :disabled="busy"
        />
        <Button
          type="button"
          severity="secondary"
          :label="t('setup.hostname.skip')"
          :disabled="busy"
          @click="step = 3"
        />
      </div>
    </form>
  </section>

  <section v-else-if="step === 3" aria-labelledby="step-heading">
    <h2 id="step-heading" ref="heading" tabindex="-1" class="mb-2 text-lg font-semibold">
      {{ t('setup.site.heading') }}
    </h2>
    <p class="mb-4 text-sk-muted">{{ t('setup.site.intro') }}</p>
    <form class="flex flex-col gap-4" novalidate @submit.prevent="createSite">
      <SkFormField :label="t('sites.fields.name.label')" :error="siteForm.errorFor('name')">
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="siteName"
            name="site_name"
            :aria-invalid="invalid ? 'true' : undefined"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('sites.fields.id.label')"
        :help="t('sites.fields.id.help')"
        :error="siteForm.errorFor('id')"
        required
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="siteId"
            name="site_id"
            mono
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="onIdInput"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('setup.site.host')"
        :help="t('setup.site.hostHelp')"
        :error="siteForm.errorFor('host')"
        required
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="siteHost"
            name="site_host"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="siteForm.clear('host')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('setup.site.target')"
        :help="t('setup.site.targetHelp')"
        :error="siteForm.errorFor('target')"
        required
      >
        <template #default="{ attrs, invalid }">
          <TextControl
            v-bind="attrs"
            v-model="target"
            name="site_target"
            mono
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="siteForm.clear('target')"
          />
        </template>
      </SkFormField>
      <SkFormField :label="t('sites.fields.upstreamTls.label')">
        <template #default="{ attrs }">
          <SwitchControl
            v-bind="attrs"
            v-model="upstreamTls"
            :label="t('sites.fields.upstreamTls.enabled')"
          />
        </template>
      </SkFormField>
      <SkFormField
        v-if="upstreamTls"
        :label="t('sites.fields.skipVerify.label')"
        :help="t('sites.fields.skipVerify.help')"
      >
        <template #default="{ attrs }">
          <SwitchControl
            v-bind="attrs"
            v-model="skipVerify"
            :label="t('sites.fields.skipVerify.enabled')"
          />
        </template>
      </SkFormField>
      <UpstreamTest :target="target" :tls="upstreamTls" :skip-verify="skipVerify" />
      <SkFormField
        :label="t('sites.fields.tlsMode.label')"
        :help="t('setup.site.tlsHelp')"
        :error="siteForm.errorFor('tls.mode')"
      >
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            v-model="tlsMode"
            :options="[
              { value: 'acme', label: t('sites.options.tlsMode.acme') },
              { value: 'none', label: t('sites.options.tlsMode.none') },
            ]"
          />
        </template>
      </SkFormField>
      <p v-if="siteForm.unmatched.value.length" role="alert" class="text-sk-danger">
        {{ siteForm.unmatched.value.join(' ') }}
      </p>
      <div class="flex gap-2">
        <Button type="submit" :label="t('setup.site.submit')" :loading="busy" :disabled="busy" />
        <Button
          type="button"
          severity="secondary"
          :label="t('setup.site.skip')"
          :disabled="busy"
          @click="step = 4"
        />
      </div>
    </form>
  </section>

  <section v-else aria-labelledby="step-heading">
    <h2 id="step-heading" ref="heading" tabindex="-1" class="mb-2 text-lg font-semibold">
      {{ t('setup.done.heading') }}
    </h2>
    <ul class="mb-4 list-disc pl-6">
      <li v-if="lastSummary.admin">{{ t('setup.done.adminSite') }}</li>
      <li v-if="lastSummary.site">{{ t('setup.done.firstSite') }}</li>
    </ul>
    <p class="mb-2">{{ t('setup.done.detect') }}</p>
    <p class="mb-4 text-sk-muted">{{ t('setup.done.next') }}</p>
    <RouterLink
      :to="{ name: 'sites' }"
      class="inline-block rounded-sk bg-sk-accent px-4 py-2 font-medium text-sk-accent-contrast hover:bg-sk-accent-hover"
    >
      {{ t('setup.done.toSites') }}
    </RouterLink>
  </section>
</template>
