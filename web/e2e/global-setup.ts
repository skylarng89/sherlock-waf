import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ApiClient, dataPlaneGet } from './lib/api'
import { buildBinary, ensureDashboardBuilt } from './lib/build'
import { nextTotp } from './lib/mfa'
import { readSetupToken, startNode, type RunningNode } from './lib/node'
import { STATE_ENV } from './lib/paths'
import type { E2EState } from './lib/state'
import { startUpstream } from './lib/upstream'

const ADMIN = { username: 'e2e-admin', password: 'correct horse battery staple 1' }
export const SEED_HOST = 'demo.e2e.test'

async function bootstrapAdmin(
  node: RunningNode,
  root: string,
  storageState: string,
): Promise<string> {
  const api = await ApiClient.create(node.baseURL)
  try {
    const token = await readSetupToken(node.dataDir)
    await api.json(await api.post('/setup/admin', { setup_token: token, ...ADMIN }), 201)
    const login = await api.json<{ status: string }>(await api.post('/auth/login', ADMIN))
    if (login.status !== 'mfa_enrol_required') throw new Error(`unexpected login ${login.status}`)
    const enrol = await api.json<{ secret: string }>(await api.post('/auth/mfa/enroll'))
    const code = await nextTotp(root, enrol.secret)
    await api.json(await api.post('/auth/mfa/enroll/confirm', { code }))
    await api.storageState(storageState)
    return enrol.secret
  } finally {
    await api.dispose()
  }
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  const root = mkdtempSync(join(tmpdir(), 'sherlock-e2e-'))
  ensureDashboardBuilt()
  const bin = buildBinary(root)
  const { upstream } = await startUpstream()

  const nodes: RunningNode[] = []
  const teardown = async () => {
    await Promise.allSettled(nodes.map((n) => n.stop()))
    await upstream.close()
    if (process.env.E2E_KEEP === '1') console.log(`[e2e] kept ${root}`)
    else rmSync(root, { recursive: true, force: true })
  }

  try {
    const flow = await startNode({
      bin,
      dataDir: join(root, 'flow'),
      seed: {
        id: 'e2e-seed',
        name: 'E2E placeholder',
        host: 'seed.e2e.invalid',
        upstreamPort: upstream.port,
        mode: 'off',
      },
    })
    nodes.push(flow)
    const main = await startNode({
      bin,
      dataDir: join(root, 'main'),
      seed: {
        id: 'demo',
        name: 'Demo shop',
        host: SEED_HOST,
        upstreamPort: upstream.port,
        mode: 'detect',
      },
    })
    nodes.push(main)

    const storageState = join(root, 'admin-state.json')
    const totpSecret = await bootstrapAdmin(main, root, storageState)
    // Gives the overview and events views something to show.
    await dataPlaneGet(main.httpPort, SEED_HOST, '/')
    await dataPlaneGet(main.httpPort, SEED_HOST, '/?id=1%27%20OR%20%271%27=%271')

    const state: E2EState = {
      root,
      upstreamPort: upstream.port,
      flow: {
        baseURL: flow.baseURL,
        httpPort: flow.httpPort,
        dataDir: flow.dataDir,
        setupToken: await readSetupToken(flow.dataDir),
      },
      main: {
        baseURL: main.baseURL,
        httpPort: main.httpPort,
        dataDir: main.dataDir,
        admin: { ...ADMIN, totpSecret },
        storageState,
        siteId: 'demo',
        siteHost: SEED_HOST,
      },
    }
    const stateFile = join(root, 'state.json')
    writeFileSync(stateFile, JSON.stringify(state, null, 2), { mode: 0o600 })
    process.env[STATE_ENV] = stateFile
  } catch (e) {
    await teardown()
    throw e
  }
  return teardown
}
