import { createServer } from 'node:net'

/** Asks the kernel for free loopback ports. Small race window between close and reuse. */
export async function freePorts(count: number): Promise<number[]> {
  const servers = await Promise.all(
    Array.from({ length: count }, () => {
      const server = createServer()
      return new Promise<ReturnType<typeof createServer>>((resolve, reject) => {
        server.once('error', reject)
        server.listen(0, '127.0.0.1', () => resolve(server))
      })
    }),
  )
  const ports = servers.map((s) => {
    const addr = s.address()
    if (!addr || typeof addr === 'string') throw new Error('no port assigned')
    return addr.port
  })
  await Promise.all(servers.map((s) => new Promise<void>((resolve) => s.close(() => resolve()))))
  return ports
}
