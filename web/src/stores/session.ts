import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { client, unwrap } from '@/api/client'
import { ApiError } from '@/api/errors'
import type { components } from '@/api/schema'

export type Me = components['schemas']['Me']

/**
 * unknown: not asked yet. anonymous: no session. partial: password accepted, MFA pending.
 * authenticated: full session.
 */
export type SessionStatus = 'unknown' | 'anonymous' | 'partial' | 'authenticated'
export type MfaStep = 'verify' | 'enrol'

export const useSessionStore = defineStore('session', () => {
  const me = ref<Me | null>(null)
  const status = ref<SessionStatus>('unknown')
  const mfaStep = ref<MfaStep>('verify')
  /** null until `/setup/status` has been read. */
  const setupRequired = ref<boolean | null>(null)

  const isAuthenticated = computed(() => status.value === 'authenticated')

  function can(permission: string | undefined): boolean {
    if (!permission) return true
    return me.value?.permissions.includes(permission) ?? false
  }

  function clear(next: SessionStatus = 'anonymous') {
    me.value = null
    status.value = next
  }

  function setMe(value: Me) {
    me.value = value
    status.value = 'authenticated'
  }

  /** Reads the session from the server. Never throws: transport errors leave the user signed out. */
  async function fetchMe(): Promise<SessionStatus> {
    try {
      const { data } = await unwrap(client.GET('/auth/me'))
      setMe(data)
    } catch (e) {
      if (e instanceof ApiError && e.kind === 'forbidden') clear('partial')
      else clear('anonymous')
    }
    return status.value
  }

  async function fetchSetupStatus(): Promise<boolean> {
    try {
      const { data } = await unwrap(client.GET('/setup/status'))
      setupRequired.value = data.setup_required
    } catch {
      // Treat as "not required": the login page is the safe default when the check fails.
      setupRequired.value = false
    }
    return setupRequired.value === true
  }

  function markSetupComplete() {
    setupRequired.value = false
  }

  /** Throws ApiError (401 bad credentials, 429 throttled). */
  async function login(
    username: string,
    password: string,
  ): Promise<'ok' | 'mfa_required' | 'mfa_enrol_required'> {
    const { data } = await unwrap(client.POST('/auth/login', { body: { username, password } }))
    if (data.status === 'ok' && data.user) {
      setMe(data.user)
    } else {
      mfaStep.value = data.status === 'mfa_enrol_required' ? 'enrol' : 'verify'
      clear('partial')
    }
    return data.status
  }

  async function verifyMfa(code: string) {
    const { data } = await unwrap(client.POST('/auth/mfa', { body: { code } }))
    setMe(data)
  }

  async function startEnrolment() {
    const { data } = await unwrap(client.POST('/auth/mfa/enroll'))
    return data
  }

  async function confirmEnrolment(code: string) {
    const { data } = await unwrap(client.POST('/auth/mfa/enroll/confirm', { body: { code } }))
    setMe(data)
  }

  /** Always ends locally, even when the server call fails (the cookie is HttpOnly and server-owned). */
  async function logout() {
    try {
      await unwrap(client.POST('/auth/logout'))
    } catch {
      // Local sign-out still proceeds; the server session expires on its own.
    } finally {
      clear('anonymous')
    }
  }

  /** Called by the API client on any 401 outside the sign-in flow. */
  function expire() {
    clear('anonymous')
  }

  return {
    me,
    status,
    mfaStep,
    setupRequired,
    isAuthenticated,
    can,
    fetchMe,
    fetchSetupStatus,
    markSetupComplete,
    login,
    verifyMfa,
    startEnrolment,
    confirmEnrolment,
    logout,
    expire,
    setMe,
  }
})
