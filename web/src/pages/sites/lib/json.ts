export type JsonObject = Record<string, unknown>

export function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

/** Reads a dotted path (`waf.paranoia_level`) from a nested object. */
export function getAt(source: unknown, path: string): unknown {
  let current: unknown = source
  for (const key of path.split('.')) {
    if (!isObject(current)) return undefined
    current = current[key]
  }
  return current
}

function omit(object: JsonObject, key: string): JsonObject {
  return Object.fromEntries(Object.entries(object).filter(([k]) => k !== key))
}

/**
 * Returns a copy of `source` with `path` set. `undefined` removes the key and any
 * parent object left empty, so "not overridden" is serialised as an omitted field.
 */
export function setAt<T extends JsonObject>(
  source: T | undefined,
  path: string,
  value: unknown,
): T {
  const keys = path.split('.')
  const write = (node: unknown, depth: number): unknown => {
    const base: JsonObject = isObject(node) ? { ...node } : {}
    const key = keys[depth] as string
    if (depth === keys.length - 1) {
      if (value === undefined) return omit(base, key)
      base[key] = value
    } else {
      const child = write(base[key], depth + 1)
      if (isObject(child) && Object.keys(child).length === 0) return omit(base, key)
      base[key] = child
    }
    return base
  }
  return write(source, 0) as T
}

/** Drops undefined, empty strings, empty arrays and empty objects, recursively. */
export function prune<T>(value: T): T | undefined {
  if (Array.isArray(value)) {
    const items = value.map((v) => prune(v)).filter((v) => v !== undefined)
    return (items.length ? items : undefined) as T | undefined
  }
  if (isObject(value)) {
    const out: JsonObject = {}
    for (const [k, v] of Object.entries(value)) {
      const pruned = prune(v)
      if (pruned !== undefined) out[k] = pruned
    }
    return (Object.keys(out).length ? out : undefined) as T | undefined
  }
  if (value === '' || value === undefined || value === null) return undefined
  return value
}

/**
 * RFC 7386 JSON Merge Patch from `before` to `after`: removed keys become `null`,
 * arrays and scalars are replaced whole. Returns undefined when nothing changed.
 */
export function mergePatch(before: unknown, after: unknown): JsonObject | undefined {
  const diff = (a: unknown, b: unknown): unknown => {
    if (isObject(a) && isObject(b)) {
      const out: JsonObject = {}
      for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
        if (!(key in b)) out[key] = null
        else if (!(key in a)) out[key] = b[key]
        else {
          const d = diff(a[key], b[key])
          if (d !== undefined) out[key] = d
        }
      }
      return Object.keys(out).length ? out : undefined
    }
    return JSON.stringify(a) === JSON.stringify(b) ? undefined : b
  }
  const result = diff(before ?? {}, after ?? {})
  return isObject(result) ? result : undefined
}
