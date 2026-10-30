import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { freePorts } from './ports'

export interface RunningNode {
  child: ChildProcess
  baseURL: string
  httpPort: number
  httpsPort: number
  dataDir: string
  logFile: string
  stop(): Promise<void>
}

export interface SeedSite {
  id: string
  name: string
  host: string
  upstreamPort: number
  mode: 'off' | 'detect' | 'block'
}

/**
 * The wizard cannot set global.admin.listen, and the data-plane admin listener
 * defaults to the fixed 127.0.0.1:9444. Importing a seed configuration before the
 * first start moves it to an ephemeral port so parallel runs and a busy 9444 are
 * harmless. A configuration needs at least one site, so a placeholder is seeded.
 */
function seedYaml(site: SeedSite): string {
  return `schema_version: 1
global:
  admin:
    listen: 127.0.0.1:0
sites:
  - id: ${site.id}
    name: ${site.name}
    hosts: [${site.host}]
    tls: { mode: none }
    upstreams: { targets: ["127.0.0.1:${site.upstreamPort}"] }
    policy: { mode: ${site.mode} }
`
}

async function pollFor<T>(
  what: string,
  timeoutMs: number,
  probe: () => Promise<T | undefined> | T | undefined,
): Promise<T> {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = await probe()
    if (value !== undefined) return value
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
    await delay(150)
  }
}

export async function startNode(opts: {
  bin: string
  dataDir: string
  seed: SeedSite
}): Promise<RunningNode> {
  mkdirSync(opts.dataDir, { recursive: true })
  const seedFile = join(opts.dataDir, 'seed.yaml')
  writeFileSync(seedFile, seedYaml(opts.seed))
  const imported = spawnSync(opts.bin, ['config', 'import', seedFile, '--data-dir', opts.dataDir], {
    encoding: 'utf8',
  })
  if (imported.status !== 0) {
    throw new Error(`config import failed: ${imported.stdout}${imported.stderr}`)
  }

  const ports = await freePorts(3)
  const [controlPort, httpPort, httpsPort] = ports as [number, number, number]
  const listen = `127.0.0.1:${controlPort}`
  const logFile = join(opts.dataDir, 'server.log')
  const env = { ...process.env }
  delete env.SHERLOCK_ADMIN_LISTEN
  const child = spawn(
    opts.bin,
    [
      'run',
      '--data-dir',
      opts.dataDir,
      '--listen',
      listen,
      '--http-port',
      String(httpPort),
      '--https-port',
      String(httpsPort),
    ],
    { env, stdio: ['ignore', 'pipe', 'pipe'] },
  )
  const log: string[] = []
  child.stdout?.on('data', (d: Buffer) => log.push(d.toString()))
  child.stderr?.on('data', (d: Buffer) => log.push(d.toString()))
  let exited = false
  child.once('exit', () => {
    exited = true
    writeFileSync(logFile, log.join(''))
  })

  const baseURL = `https://${listen}`
  try {
    await pollFor('the control plane /healthz', 60_000, async () => {
      if (exited) throw new Error(`sherlock exited early:\n${log.join('')}`)
      try {
        const res = await fetchInsecure(`${baseURL}/healthz`)
        return res === 200 ? true : undefined
      } catch {
        return undefined
      }
    })
  } catch (e) {
    child.kill('SIGKILL')
    writeFileSync(logFile, log.join(''))
    throw e
  }

  return {
    child,
    baseURL,
    httpPort,
    httpsPort,
    dataDir: opts.dataDir,
    logFile,
    async stop() {
      if (exited) return
      const done = new Promise<void>((resolve) => child.once('exit', () => resolve()))
      child.kill('SIGTERM')
      const killer = setTimeout(() => child.kill('SIGKILL'), 20_000)
      await done
      clearTimeout(killer)
    },
  }
}

export async function readSetupToken(dataDir: string): Promise<string> {
  const file = join(dataDir, 'setup-token')
  return pollFor('the setup-token file', 30_000, () => {
    if (!existsSync(file)) return undefined
    const token = readFileSync(file, 'utf8').trim()
    return token === '' ? undefined : token
  })
}

/** Status-only probe of a self-signed HTTPS endpoint without touching global TLS settings. */
async function fetchInsecure(url: string): Promise<number> {
  const { request } = await import('node:https')
  return new Promise((resolve, reject) => {
    const req = request(url, { rejectUnauthorized: false, agent: false }, (res) => {
      res.resume()
      resolve(res.statusCode ?? 0)
    })
    req.setTimeout(3_000, () => req.destroy(new Error('timeout')))
    req.on('error', reject)
    req.end()
  })
}
