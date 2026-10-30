import { createHmac } from 'node:crypto'

const PERIOD_SECONDS = 30
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** Decodes RFC 4648 base32, ignoring spaces and padding. */
export function base32Decode(input: string): Buffer {
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const char of input.replace(/[\s=]/g, '').toUpperCase()) {
    const index = ALPHABET.indexOf(char)
    if (index < 0) throw new Error(`invalid base32 character ${char}`)
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

/** RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s), implemented independently of the server. */
export function totpAtStep(secret: string, step: number): string {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const mac = createHmac('sha1', base32Decode(secret)).update(counter).digest()
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f
  const binary =
    (((mac[offset] ?? 0) & 0x7f) << 24) |
    ((mac[offset + 1] ?? 0) << 16) |
    ((mac[offset + 2] ?? 0) << 8) |
    (mac[offset + 3] ?? 0)
  return String(binary % 1_000_000).padStart(6, '0')
}

export function currentStep(nowMs: number = Date.now()): number {
  return Math.floor(nowMs / 1000 / PERIOD_SECONDS)
}
