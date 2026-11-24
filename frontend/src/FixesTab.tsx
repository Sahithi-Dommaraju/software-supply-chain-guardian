import { useState } from 'react'
import type { Decision, FixCard, Results } from './types'
import { AiNote, LlmBanner, Snippets } from './Day2Common'

function usePersisted(key: string): [string, (v: string) => void] {
  const [v, setV] = useState(() => { try { return localStorage.getItem(key) ?? '' } catch { return '' } })
  return [v, (x) => { setV(x); try { localStorage.setItem(key, x) } catch { /* not persisted */ } }]
}

export default function FixesTab({ scanId, data, decisions, onDecided }: {
  scanId: string; data: NonNullable<Results['remediate']>; decisions: Record<string, Decision>; onDecided: () => void
}) {
  const [who, setWho] = usePersisted('guardian-approver')
  const decided = Object.values(decisions)
  return (
    <div className="day2">
      <LlmBanner llm={data.llm} what="read changelogs and app usage to explain what may break" />
      <section className="card approver">
        <div>
          <b>Human approval</b>
          <div className="small muted">Approving records the decision only. Nothing is changed in the repository; build and test come later.
            {' '}{decided.filter((d) => d.decision === 'approved').length} approved · {decided.filter((d) => d.decision === 'rejected').length} rejected · {data.cards.length - decided.length} pending</div>
        </div>
        <label className="small">Your name <input value={who} onChange={(e) => setWho(e.target.value)} placeholder="e.g. Vyshnav" aria-label="Approver name" /></label>
      </section>
      {data.errors.length > 0 && <div className="alert">Could not plan a fix for: {data.errors.map((e) => `${e.package} (${e.error})`).join('; ')}</div>}
      {data.cards.map((c) => <Card key={c.id} c={c} scanId={scanId} who={who} decision={decisions[c.id]} onDecided={onDecided} />)}
      {data.cards.length === 0 && <div className="card muted">No critical or high risks to fix.</div>}
    </div>
  )
}

function Card({ c, scanId, who, decision, onDecided }: { c: FixCard; scanId: string; who: string; decision?: Decision; onDecided: () => void }) {
  const [note, setNote] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const ch = c.change
  const ai = c.ai.ok ? c.ai.answer! : null

  async function decide(d: 'approved' | 'rejected') {
    if (!who.trim()) return setErr('Enter your name above first.')
    setBusy(true)
    setErr('')
    const r = await fetch(`/api/scans/${scanId}/decisions`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ card_id: c.id, decision: d, decided_by: who, note }),
    }).catch(() => null)
    setBusy(false)
    if (!r?.ok) return setErr(r ? (await r.json()).detail?.toString() ?? 'Failed' : 'Backend not reachable')
    onDecided()
  }

  return (
    <section className={`card fixcard ${decision?.decision ?? ''}`}>
      <div className="fix-head">
        <div>
          <div className="small muted">#{c.rank} · {c.package}@{c.version} · <span className="chip">{c.action}</span></div>
          <h2>{c.title}</h2>
          {c.also_fixes && <div className="small muted">Also fixes {c.also_fixes.join(', ')}</div>}
        </div>
        <div className="score-move"><span className={`sev ${c.band}`}>{c.score_before.toFixed(1)}</span> → <span className={`sev ${c.band_after ?? 'low'}`}>{c.score_after.toFixed(1)}</span></div>
      </div>
      <div className="fix-grid">
        <div>
          <h3>Change</h3>
          {ch ? <p className="mono small">{ch.package}: {ch.from} → {ch.to} <span className="chip">{ch.jump} jump</span><br />{ch.manifest} · {ch.field}</p>
              : <p className="small">No version change possible.</p>}
          {c.patch && <pre className="code diff">{c.patch}</pre>}
          {c.resolution && c.resolution.length > 1 && <p className="small mono">Resolves to: {c.resolution.map((s) => `${s.package}@${s.version}`).join(' → ')}</p>}
        </div>
        <div>
          <h3>Risk reduction</h3>
          <p className="small">Removes {c.advisories_removed.length} advisor{c.advisories_removed.length === 1 ? 'y' : 'ies'}
            {c.cves_removed.length > 0 && <> ({c.cves_removed.join(', ')})</>}.
            {c.remaining.length > 0 ? <> Still open: <span className="mono">{c.remaining.join(', ')}</span>.</> : ' Nothing left open on this package.'}</p>
          <h3>Rollback</h3>
          <p className="small">{c.rollback ? <>{c.rollback.how} <span className="mono">({c.rollback.version})</span></> : 'n/a'}</p>
        </div>
        <div>
          <h3>Compatibility <AiNote ai={c.ai} /></h3>
          <p className="small">Version jump: <b>{c.compatibility.jump ?? 'n/a'}</b>{ai && <> · AI breaking risk: <b className={`sev-text ${ai.breaking_risk === 'high' ? 'critical' : ai.breaking_risk === 'medium' ? 'medium' : 'low'}`}>{ai.breaking_risk}</b></>}</p>
          {ai && <p className="small">{ai.summary}</p>}
          {ai && ai.notes?.length > 0 && <ul className="small">{ai.notes.map((n: any, i: number) => <li key={i}>{n.text}{n.file && <span className="mono muted"> ({n.file}:{n.line})</span>}</li>)}</ul>}
          <p className="small muted">Changelog: {c.evidence.changelog?.startsWith('http') ? <a href={c.evidence.changelog} target="_blank" rel="noreferrer">{c.evidence.changelog}</a> : c.evidence.changelog ?? 'n/a'}</p>
        </div>
      </div>
      <Snippets snippets={c.usage_snippets} cites={(ai?.notes ?? []).filter((n: any) => n.file)} />
      <div className="decision">
        {decision ? (
          <div className={`decided ${decision.decision}`}>
            {decision.decision === 'approved' ? '✓ Approved' : '✕ Rejected'} by <b>{decision.decided_by}</b> at {new Date(decision.decided_at).toLocaleString()}
            {decision.note && <> — “{decision.note}”</>}
          </div>
        ) : (
          <>
            <input placeholder="Note (optional): why approve or reject" value={note} onChange={(e) => setNote(e.target.value)} aria-label="Decision note" />
            <button className="approve" disabled={busy || c.action === 'replace'} onClick={() => decide('approved')}>Approve</button>
            <button className="reject" disabled={busy} onClick={() => decide('rejected')}>Reject</button>
          </>
        )}
        {err && <span className="note small">{err}</span>}
      </div>
    </section>
  )
}
