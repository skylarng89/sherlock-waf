import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

export interface Upstream {
  port: number
  close(): Promise<void>
}

/** A tiny origin server: every request is answered with the text "origin". */
export async function startUpstream(): Promise<{ upstream: Upstream; server: Server }> {
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
    res.end('origin')
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const { port } = server.address() as AddressInfo
  return {
    server,
    upstream: {
      port,
      close: () =>
        new Promise<void>((resolve) => {
          server.close(() => resolve())
          server.closeAllConnections()
        }),
    },
  }
}
