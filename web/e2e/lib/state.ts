import { readFileSync } from 'node:fs'
import { STATE_ENV } from './paths'

export interface NodeInfo {
  baseURL: string
  /** Data plane HTTP port; requests carry a Host header to select the site. */
  httpPort: number
  dataDir: string
}

export interface AdminCredentials {
  username: string
  password: string
  totpSecret: string
}

export interface E2EState {
  root: string
  upstreamPort: number
  /** A fresh node: only the setup wizard test touches it. */
  flow: NodeInfo & { setupToken: string }
  /** A bootstrapped node (admin + one site) shared by every other spec. */
  main: NodeInfo & {
    admin: AdminCredentials
    storageState: string
    siteId: string
    siteHost: string
  }
}

export function readState(): E2EState {
  const file = process.env[STATE_ENV]
  if (!file) throw new Error(`${STATE_ENV} is not set: the Playwright global setup did not run`)
  return JSON.parse(readFileSync(file, 'utf8')) as E2EState
}
