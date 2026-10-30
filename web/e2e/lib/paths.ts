import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

export const WEB_DIR = resolve(here, '..', '..')
export const REPO_ROOT = resolve(WEB_DIR, '..')
export const DIST_DIR = resolve(REPO_ROOT, 'internal', 'webui', 'dist')
/** Where the global setup records the nodes it started; read by the fixtures. */
export const STATE_ENV = 'SHERLOCK_E2E_STATE'
