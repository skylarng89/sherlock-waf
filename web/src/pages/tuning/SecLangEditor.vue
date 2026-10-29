<script setup lang="ts">
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { syntaxHighlighting } from '@codemirror/language'
import { EditorState, RangeSetBuilder, StateEffect, StateField } from '@codemirror/state'
import { Decoration, EditorView, keymap, lineNumbers, type DecorationSet } from '@codemirror/view'
import { tagHighlighter, tags } from '@lezer/highlight'
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { seclang } from './seclang'

const props = defineProps<{
  modelValue: string
  readonly?: boolean
  /** Id of the visible label element. */
  labelledby: string
  describedby?: string
  /** 1-based lines carrying a validation issue. */
  issueLines: number[]
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()

const host = ref<HTMLDivElement>()
let view: EditorView | undefined

const setIssues = StateEffect.define<number[]>()
const issueField = StateField.define<DecorationSet>({
  create: () => Decoration.none,
  update(value, tr) {
    let next = value.map(tr.changes)
    for (const e of tr.effects) {
      if (!e.is(setIssues)) continue
      const builder = new RangeSetBuilder<Decoration>()
      const doc = tr.state.doc
      for (const n of [...new Set(e.value)].sort((a, b) => a - b)) {
        if (n >= 1 && n <= doc.lines) {
          builder.add(doc.line(n).from, doc.line(n).from, Decoration.line({ class: 'sl-issue' }))
        }
      }
      next = builder.finish()
    }
    return next
  },
  provide: (f) => EditorView.decorations.from(f),
})

const highlighter = tagHighlighter([
  { tag: tags.keyword, class: 'sl-keyword' },
  { tag: tags.string, class: 'sl-string' },
  { tag: tags.comment, class: 'sl-comment' },
  { tag: tags.operator, class: 'sl-operator' },
  { tag: tags.variableName, class: 'sl-variable' },
  { tag: tags.number, class: 'sl-number' },
])

// Colours come from the dashboard tokens, which are contrast-tested in both themes. Issue
// lines also get a wavy underline so colour is never the only signal.
const theme = EditorView.theme({
  '&': {
    backgroundColor: 'var(--sk-surface)',
    color: 'var(--sk-text)',
    border: '1px solid var(--sk-border-strong)',
    borderRadius: 'var(--sk-radius)',
    maxHeight: '32rem',
  },
  '&.cm-focused': { outline: '2px solid var(--sk-focus)', outlineOffset: '2px' },
  '.cm-scroller': { fontFamily: 'ui-monospace, monospace', fontSize: '0.875rem', overflow: 'auto' },
  '.cm-content': { minHeight: '12rem', caretColor: 'var(--sk-text)' },
  '.cm-cursor': { borderLeftColor: 'var(--sk-text)' },
  '.cm-gutters': {
    backgroundColor: 'var(--sk-surface-muted)',
    color: 'var(--sk-muted)',
    borderRight: '1px solid var(--sk-border)',
  },
  '.cm-selectionBackground, &.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground':
    { backgroundColor: 'var(--sk-info-bg)' },
  '.sl-keyword': { color: 'var(--sk-accent)', fontWeight: '600' },
  '.sl-string': { color: 'var(--sk-success)' },
  '.sl-comment': { color: 'var(--sk-muted)', fontStyle: 'italic' },
  '.sl-operator': { color: 'var(--sk-warning)' },
  '.sl-variable': { color: 'var(--sk-info)' },
  '.sl-number': { color: 'var(--sk-text)' },
  '.sl-issue': {
    backgroundColor: 'var(--sk-danger-bg)',
    textDecoration: 'underline wavy var(--sk-danger)',
  },
})

function nonce(): string | undefined {
  const content = document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content')
  return content && !content.startsWith('{{') ? content : undefined
}

onMounted(() => {
  if (!host.value) return
  const n = nonce()
  view = new EditorView({
    parent: host.value,
    state: EditorState.create({
      doc: props.modelValue,
      extensions: [
        lineNumbers(),
        history(),
        // No Tab binding on purpose: Tab leaves the editor, so keyboard users are never trapped.
        keymap.of([...defaultKeymap, ...historyKeymap]),
        seclang,
        syntaxHighlighting(highlighter),
        issueField,
        theme,
        EditorState.readOnly.of(Boolean(props.readonly)),
        EditorView.contentAttributes.of({
          'aria-labelledby': props.labelledby,
          ...(props.describedby ? { 'aria-describedby': props.describedby } : {}),
          'aria-multiline': 'true',
          'data-testid': 'seclang-editor',
          spellcheck: 'false',
          autocapitalize: 'off',
        }),
        ...(n ? [EditorView.cspNonce.of(n)] : []),
        EditorView.updateListener.of((u) => {
          if (u.docChanged) emit('update:modelValue', u.state.doc.toString())
        }),
      ],
    }),
  })
  view.dispatch({ effects: setIssues.of(props.issueLines) })
})

onBeforeUnmount(() => view?.destroy())

watch(
  () => props.modelValue,
  (value) => {
    if (view && value !== view.state.doc.toString()) {
      view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: value } })
    }
  },
)
watch(
  () => props.issueLines,
  (lines) => view?.dispatch({ effects: setIssues.of(lines) }),
)

function goToLine(n: number) {
  if (!view) return
  const line = view.state.doc.line(Math.min(Math.max(n, 1), view.state.doc.lines))
  view.dispatch({ selection: { anchor: line.from }, scrollIntoView: true })
  view.focus()
}
defineExpose({ goToLine })
</script>

<template>
  <div ref="host" />
</template>
