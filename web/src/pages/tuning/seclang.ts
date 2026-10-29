import { StreamLanguage, type StreamParser } from '@codemirror/language'

/**
 * A deliberately small SecLang tokenizer: directives, variables, operators, quoted strings,
 * numbers and comments. It only colours text; the server does the real validation.
 */
export const seclangParser: StreamParser<null> = {
  name: 'seclang',
  startState: () => null,
  token(stream) {
    if (stream.eatSpace()) return null
    if (stream.sol() && stream.peek() === '#') {
      stream.skipToEnd()
      return 'comment'
    }
    const ch = stream.peek()
    if (ch === '"' || ch === "'") {
      stream.next()
      while (!stream.eol()) {
        const c = stream.next()
        if (c === '\\') stream.next()
        else if (c === ch) break
      }
      return 'string'
    }
    if (stream.match(/^Sec[A-Za-z]+/)) return 'keyword'
    if (stream.match(/^[!&]?@[A-Za-z]+/)) return 'operator'
    if (stream.match(/^[!&]?[A-Z][A-Z_]+(?::[^\s|"',]+)?/)) return 'variableName'
    if (stream.match(/^\d+/)) return 'number'
    if (stream.match(/^\\$/)) return 'meta'
    stream.next()
    return null
  },
}

export const seclang = StreamLanguage.define(seclangParser)
