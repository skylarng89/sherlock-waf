// Minimal QR Code encoder: byte mode, error-correction level M, versions 1-40.
// Follows ISO/IEC 18004; written in-tree so the TOTP secret never reaches a
// third-party library or a remote service (see docs/engineering/dashboard.md).

const ECC_PER_BLOCK_M = [
  -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28,
  28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
]
const BLOCKS_M = [
  -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25,
  26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
]
const MASK_COUNT = 8
const FORMAT_BITS_M = 0

function rawModules(ver: number): number {
  let n = (16 * ver + 128) * ver + 64
  if (ver >= 2) {
    const align = Math.floor(ver / 7) + 2
    n -= (25 * align - 10) * align - 55
    if (ver >= 7) n -= 36
  }
  return n
}

function dataCodewords(ver: number): number {
  return Math.floor(rawModules(ver) / 8) - (ECC_PER_BLOCK_M[ver] ?? 0) * (BLOCKS_M[ver] ?? 0)
}

function gfMul(x: number, y: number): number {
  let z = 0
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d)
    z ^= ((y >>> i) & 1) * x
  }
  return z
}

function rsDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0)
  result[degree - 1] = 1
  let root = 1
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j] ?? 0, root)
      if (j + 1 < degree) result[j] = (result[j] ?? 0) ^ (result[j + 1] ?? 0)
    }
    root = gfMul(root, 2)
  }
  return result
}

function rsRemainder(data: number[], divisor: number[]): number[] {
  const result = new Array<number>(divisor.length).fill(0)
  for (const b of data) {
    const factor = b ^ (result.shift() ?? 0)
    result.push(0)
    divisor.forEach((coef, i) => {
      result[i] = (result[i] ?? 0) ^ gfMul(coef, factor)
    })
  }
  return result
}

function utf8(text: string): number[] {
  return Array.from(new TextEncoder().encode(text))
}

function buildData(bytes: number[], ver: number): number[] {
  const bits: number[] = []
  const push = (value: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((value >>> i) & 1)
  }
  push(0b0100, 4)
  push(bytes.length, ver <= 9 ? 8 : 16)
  bytes.forEach((b) => push(b, 8))
  const capacityBits = dataCodewords(ver) * 8
  push(0, Math.min(4, capacityBits - bits.length))
  push(0, (8 - (bits.length % 8)) % 8)
  const out: number[] = []
  for (let i = 0; i < bits.length; i += 8) {
    out.push(parseInt(bits.slice(i, i + 8).join(''), 2))
  }
  for (let pad = 0xec; out.length < dataCodewords(ver); pad ^= 0xec ^ 0x11) out.push(pad)
  return out
}

function interleave(data: number[], ver: number): number[] {
  const numBlocks = BLOCKS_M[ver] ?? 1
  const eccLen = ECC_PER_BLOCK_M[ver] ?? 0
  const raw = Math.floor(rawModules(ver) / 8)
  const shortBlocks = numBlocks - (raw % numBlocks)
  const shortLen = Math.floor(raw / numBlocks)
  const divisor = rsDivisor(eccLen)
  const blocks: number[][] = []
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const len = shortLen - eccLen + (i < shortBlocks ? 0 : 1)
    const dat = data.slice(k, k + len)
    k += len
    const ecc = rsRemainder(dat, divisor)
    if (i < shortBlocks) dat.push(0)
    blocks.push(dat.concat(ecc))
  }
  const result: number[] = []
  for (let i = 0; i < (blocks[0]?.length ?? 0); i++) {
    blocks.forEach((block, j) => {
      if (i !== shortLen - eccLen || j >= shortBlocks) result.push(block[i] ?? 0)
    })
  }
  return result
}

function alignmentPositions(ver: number): number[] {
  if (ver === 1) return []
  const n = Math.floor(ver / 7) + 2
  const step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (n * 2 - 2)) * 2
  const result = [6]
  for (let pos = ver * 4 + 17 - 7; result.length < n; pos -= step) result.splice(1, 0, pos)
  return result
}

class Grid {
  readonly size: number
  readonly modules: boolean[][]
  readonly fn: boolean[][]

  constructor(readonly ver: number) {
    this.size = ver * 4 + 17
    this.modules = Array.from({ length: this.size }, () =>
      new Array<boolean>(this.size).fill(false),
    )
    this.fn = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false))
    this.drawFunctionPatterns()
  }

  private set(x: number, y: number, dark: boolean) {
    const row = this.modules[y]
    const fnRow = this.fn[y]
    if (!row || !fnRow) return
    row[x] = dark
    fnRow[x] = true
  }

  private drawFunctionPatterns() {
    const { size, ver } = this
    for (let i = 0; i < size; i++) {
      this.set(6, i, i % 2 === 0)
      this.set(i, 6, i % 2 === 0)
    }
    for (const [cx, cy] of [
      [3, 3],
      [size - 4, 3],
      [3, size - 4],
    ] as const) {
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const dist = Math.max(Math.abs(dx), Math.abs(dy))
          const x = cx + dx
          const y = cy + dy
          if (x >= 0 && x < size && y >= 0 && y < size) this.set(x, y, dist !== 2 && dist !== 4)
        }
      }
    }
    const pos = alignmentPositions(ver)
    pos.forEach((cy, i) => {
      pos.forEach((cx, j) => {
        const corner =
          (i === 0 && j === 0) ||
          (i === 0 && j === pos.length - 1) ||
          (i === pos.length - 1 && j === 0)
        if (corner) return
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) {
            this.set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
          }
        }
      })
    })
    this.drawFormat(0)
    if (ver >= 7) {
      let rem = ver
      for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
      const bits = (ver << 12) | rem
      for (let i = 0; i < 18; i++) {
        const bit = ((bits >>> i) & 1) !== 0
        const a = size - 11 + (i % 3)
        const b = Math.floor(i / 3)
        this.set(a, b, bit)
        this.set(b, a, bit)
      }
    }
  }

  drawFormat(mask: number) {
    const { size } = this
    const data = (FORMAT_BITS_M << 3) | mask
    let rem = data
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537)
    const bits = ((data << 10) | rem) ^ 0x5412
    const bit = (i: number) => ((bits >>> i) & 1) !== 0
    for (let i = 0; i <= 5; i++) this.set(8, i, bit(i))
    this.set(8, 7, bit(6))
    this.set(8, 8, bit(7))
    this.set(7, 8, bit(8))
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(i))
    for (let i = 0; i < 8; i++) this.set(size - 1 - i, 8, bit(i))
    for (let i = 8; i < 15; i++) this.set(8, size - 15 + i, bit(i))
    this.set(8, size - 8, true)
  }

  drawCodewords(data: number[]) {
    const { size } = this
    let i = 0
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5
      for (let vert = 0; vert < size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j
          const upward = ((right + 1) & 2) === 0
          const y = upward ? size - 1 - vert : vert
          if (!this.fn[y]?.[x] && i < data.length * 8) {
            const row = this.modules[y]
            if (row) row[x] = (((data[i >>> 3] ?? 0) >>> (7 - (i & 7))) & 1) !== 0
            i++
          }
        }
      }
    }
  }

  applyMask(mask: number) {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        const invert = [
          (x + y) % 2 === 0,
          y % 2 === 0,
          x % 3 === 0,
          (x + y) % 3 === 0,
          (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
          ((x * y) % 2) + ((x * y) % 3) === 0,
          (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
          (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
        ][mask]
        const row = this.modules[y]
        if (row && invert && !this.fn[y]?.[x]) row[x] = !row[x]
      }
    }
  }

  // Simplified ISO penalty (runs, 2x2 blocks, dark balance): any mask is valid,
  // the score only improves scanability.
  penalty(): number {
    const { size, modules } = this
    let score = 0
    const runs = (get: (a: number, b: number) => boolean) => {
      for (let a = 0; a < size; a++) {
        let run = 1
        for (let b = 1; b < size; b++) {
          if (get(a, b) === get(a, b - 1)) {
            run++
            if (run === 5) score += 3
            else if (run > 5) score++
          } else run = 1
        }
      }
    }
    runs((a, b) => modules[a]?.[b] ?? false)
    runs((a, b) => modules[b]?.[a] ?? false)
    let dark = 0
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (modules[y]?.[x]) dark++
        if (
          x + 1 < size &&
          y + 1 < size &&
          modules[y]?.[x] === modules[y]?.[x + 1] &&
          modules[y]?.[x] === modules[y + 1]?.[x] &&
          modules[y]?.[x] === modules[y + 1]?.[x + 1]
        )
          score += 3
      }
    }
    const percent = (dark * 100) / (size * size)
    return score + Math.floor(Math.abs(percent - 50) / 5) * 10
  }
}

/** Encodes text as a QR matrix (true = dark module). Throws if it exceeds version 40. */
export function qrMatrix(text: string): boolean[][] {
  const bytes = utf8(text)
  let ver = 1
  for (; ver <= 40; ver++) {
    const lenBits = ver <= 9 ? 8 : 16
    if (4 + lenBits + bytes.length * 8 <= dataCodewords(ver) * 8) break
  }
  if (ver > 40) throw new RangeError('text too long for a QR code')

  const codewords = interleave(buildData(bytes, ver), ver)
  let best: Grid | undefined
  let bestScore = Infinity
  for (let mask = 0; mask < MASK_COUNT; mask++) {
    const grid = new Grid(ver)
    grid.drawCodewords(codewords)
    grid.applyMask(mask)
    grid.drawFormat(mask)
    const score = grid.penalty()
    if (score < bestScore) {
      best = grid
      bestScore = score
    }
  }
  return (best ?? new Grid(ver)).modules
}
