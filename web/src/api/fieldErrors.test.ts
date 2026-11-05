import { describe, expect, it } from 'vitest'
import { ApiError } from './errors'
import { mapFieldErrors, pointerToPath, useFormErrors } from './fieldErrors'

const err = (fieldErrors: Record<string, string[]>) =>
  new ApiError({ status: 422, title: 'Invalid', fieldErrors })

describe('pointerToPath', () => {
  it.each([
    ['/name', 'name'],
    ['/hosts/0/name', 'hosts.0.name'],
    ['/a~1b/c~0d', 'a/b.c~d'],
    ['', ''],
  ])('%s -> %s', (pointer, path) => expect(pointerToPath(pointer)).toBe(path))
})

describe('mapFieldErrors', () => {
  it('maps pointers to form paths and joins messages', () => {
    const { fields, unmatched } = mapFieldErrors(err({ '/hosts/0': ['bad', 'dup'] }))
    expect(fields).toEqual({ 'hosts.0': 'bad dup' })
    expect(unmatched).toEqual([])
  })

  it('applies aliases by pointer or dotted path', () => {
    const { fields } = mapFieldErrors(
      err({ '/upstream/url': ['bad'], '/rate_limit': ['low'] }),
      undefined,
      {
        aliases: { '/upstream/url': 'upstreamUrl', rate_limit: 'rateLimit' },
      },
    )
    expect(fields).toEqual({ upstreamUrl: 'bad', rateLimit: 'low' })
  })

  it('reports errors for fields the form does not render instead of dropping them', () => {
    const { fields, unmatched } = mapFieldErrors(err({ '/name': ['req'], '/other': ['x'] }), [
      'name',
    ])
    expect(fields).toEqual({ name: 'req' })
    expect(unmatched).toEqual(['other: x'])
  })
})

describe('useFormErrors', () => {
  it('applies only ApiErrors that carry field errors', () => {
    const form = useFormErrors()
    expect(form.apply(new Error('x'))).toBe(false)
    expect(form.apply(new ApiError({ status: 500 }))).toBe(false)
    expect(form.apply(err({ '/name': ['required'] }))).toBe(true)
    expect(form.errorFor('name')).toBe('required')
    expect(form.hasErrors.value).toBe(true)
  })

  it('clears one field or all', () => {
    const form = useFormErrors()
    form.apply(err({ '/a': ['1'], '/b': ['2'] }))
    form.clear('a')
    expect(form.errorFor('a')).toBeUndefined()
    expect(form.errorFor('b')).toBe('2')
    form.clear()
    expect(form.hasErrors.value).toBe(false)
  })
})
