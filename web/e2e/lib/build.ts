import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { DIST_DIR, REPO_ROOT, WEB_DIR } from './paths'

function newestMtime(path: string): number {
  const stat = statSync(path)
  if (!stat.isDirectory()) return stat.mtimeMs
  return readdirSync(path).reduce((max, entry) => {
    if (entry === 'node_modules') return max
    return Math.max(max, newestMtime(join(path, entry)))
  }, stat.mtimeMs)
}

function run(cmd: string, args: string[], cwd: string, env: NodeJS.ProcessEnv = process.env): void {
  const res = spawnSync(cmd, args, { cwd, env, stdio: 'inherit' })
  if (res.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed (exit ${res.status})`)
}

/** Rebuilds the embedded dashboard when any source file is newer than the built index.html. */
export function ensureDashboardBuilt(): void {
  const index = join(DIST_DIR, 'index.html')
  const sources = ['src', 'index.html', 'package.json', 'vite.config.ts', 'pnpm-lock.yaml']
  const newest = Math.max(...sources.map((s) => newestMtime(join(WEB_DIR, s))))
  if (process.env.E2E_SKIP_BUILD === '1' && existsSync(index)) return
  if (existsSync(index) && statSync(index).mtimeMs >= newest) return
  console.log('[e2e] dashboard is stale, running pnpm build')
  run('pnpm', ['build'], WEB_DIR)
}

/** Builds the single Go binary (which embeds internal/webui/dist) into `outDir`. */
export function buildBinary(outDir: string): string {
  const bin = join(outDir, 'sherlock')
  run('go', ['build', '-trimpath', '-o', bin, './cmd/sherlock'], REPO_ROOT, {
    ...process.env,
    CGO_ENABLED: '0',
  })
  return bin
}
