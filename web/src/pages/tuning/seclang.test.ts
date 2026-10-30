import { StringStream } from '@codemirror/language'
import { describe, expect, it } from 'vitest'
import { seclangParser } from './seclang'

function tokens(line: string): [string, string | null][] {
  const stream = new StringStream(line, 2, 2)
  const out: [string, string | null][] = []
  while (!stream.eol()) {
    stream.start = stream.pos
    const type = seclangParser.token(stream, null)
    if (stream.pos === stream.start) throw new Error('tokenizer made no progress')
    if (type) out.push([stream.current(), type])
  }
  return out
}

describe('seclang tokenizer', () => {
  it('colours directives, variables, operators and strings', () => {
    expect(tokens('SecRule ARGS:q "@rx evil" "id:10001,phase:2,deny"')).toEqual([
      ['SecRule', 'keyword'],
      ['ARGS:q', 'variableName'],
      ['"@rx evil"', 'string'],
      ['"id:10001,phase:2,deny"', 'string'],
    ])
  })

  it('treats a leading hash as a comment and handles escaped quotes', () => {
    expect(tokens('# SecRule ARGS')).toEqual([['# SecRule ARGS', 'comment']])
    expect(tokens('"a \\" b" 42')).toEqual([
      ['"a \\" b"', 'string'],
      ['42', 'number'],
    ])
  })

  it('always makes progress on odd input', () => {
    expect(() => tokens('\\ ~~ "unterminated')).not.toThrow()
  })
})
