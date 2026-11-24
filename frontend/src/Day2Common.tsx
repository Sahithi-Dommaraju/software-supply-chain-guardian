import type { AiResult, Citation, LlmStatus, Snippet } from './types'

/** Banner saying whether the LLM ran, so AI-derived fields are never mistaken for tool facts. */
export function LlmBanner({ llm, what }: { llm?: LlmStatus; what: string }) {
  if (!llm) return null
  return llm.enabled
    ? <div className="llm-banner ok">AI ({llm.model}) {what}{llm.answered != null && `: ${llm.answered} answered`}{llm.candidates != null && ` of ${llm.candidates} asked`}. Every AI answer is checked by the Validator; failed answers fall back to the rule result.</div>
    : <div className="llm-banner off">AI explanation unavailable: no API key configured. Results below are rule-based only. To enable it, put <code>GROQ_API_KEY=…</code> in <code>backend/.env</code> and restart the backend.</div>
}

export function AiNote({ ai }: { ai: AiResult }) {
  if (ai.ok) return <span className="chip ai" title={`${ai.model}${ai.cached ? ' (cached)' : ''}, attempt ${ai.attempts}`}>AI inference{ai.cached ? ' · cached' : ''}</span>
  return <span className="chip" title={ai.problems?.join('\n')}>{ai.reason}</span>
}

/** Code with numbered lines; cited lines highlighted. */
export function CodeView({ file, lines, start = 1, highlight = [] }: { file: string; lines: string[]; start?: number; highlight?: number[] }) {
  const hl = new Set(highlight)
  return (
    <div className="codeview">
      <div className="codeview-file mono">{file}</div>
      <pre>{lines.map((l, i) => (
        <div key={i} className={hl.has(start + i) ? 'hl' : ''}><span className="ln">{start + i}</span>{l || ' '}</div>
      ))}</pre>
    </div>
  )
}

export function Snippets({ snippets, cites }: { snippets?: Snippet[]; cites?: Citation[] }) {
  if (!snippets?.length) return null
  return <>{snippets.map((s) => (
    <CodeView key={s.file} file={s.file} lines={s.lines} start={s.start}
              highlight={(cites ?? []).filter((c) => c.file === s.file).map((c) => c.line)} />
  ))}</>
}
