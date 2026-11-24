import { useState } from 'react'
import type { Results } from './types'
import { artifactUrl } from './types'
import { Sev } from './Vulnerabilities'

const RISKS = ['critical', 'high', 'medium', 'low', 'review'] as const

export default function Report({ scanId, data, repoUrl, sha }: {
  scanId: string; data: NonNullable<Results['evidence']>; repoUrl: string; sha: string | null
}) {
  const [risk, setRisk] = useState<string>('all')
  const [type, setType] = useState('all')
  const r = data.report
  const shown = data.bundles.filter((b) => (risk === 'all' || b.initial_risk.level === risk) && (type === 'all' || b.type === type))
  const fileUrl = (ref: string, line?: number | null) =>
    `${repoUrl.replace(/\.git$/, '')}/blob/${sha}/${ref}${line ? `#L${line}` : ''}`

  return (
    <div className="report">
      <section className="card sbom-head">
        <div>
          <div className="eyebrow">Evidence report</div>
          <h2>{r.repository} @ <span className="mono">{r.commit_sha.slice(0, 12)}</span></h2>
          <div className="muted small">
            Generated {r.generated_at} · {r.inventory.components} components · {r.by_type.vulnerability} vulnerability
            and {r.by_type.suspicious} suspicious-pattern findings. Built from tool output only; no AI-written text.
          </div>
        </div>
        <div className="btn-row">
          <a className="button" href={artifactUrl(scanId, data.artifacts.markdown)}>Report (Markdown)</a>
          <a className="button secondary" href={artifactUrl(scanId, data.artifacts.json)}>JSON</a>
        </div>
      </section>

      <div className="kpis">
        {RISKS.map((l) => (
          <button key={l} className={`kpi kpi-btn ${risk === l ? 'on' : ''}`} onClick={() => setRisk(risk === l ? 'all' : l)}>
            <div className={`kpi-value sev-text ${l}`}>{r.risk_counts[l] ?? 0}</div>
            <div className="kpi-label">{l} initial risk</div>
          </button>
        ))}
      </div>

      <div className="two-col">
        <section className="card">
          <h2>Acceptance checklist</h2>
          <ul className="checklist">
            {r.checklist.map((c) => <li key={c.item} className={c.done ? 'ok' : 'no'}><span>{c.done ? '✓' : '✕'}</span>{c.item}</li>)}
          </ul>
        </section>
        <section className="card">
          <h2>Coverage and gaps</h2>
          <p className="small muted">What this scan did not check. None of these mean "clean".</p>
          <ul className="gaps">{r.coverage.gaps.map((g) => <li key={g}>{g}</li>)}</ul>
        </section>
      </div>

      <section className="card">
        <div className="row-between">
          <h2>Evidence bundles ({shown.length})</h2>
          <div className="seg">
            {[['all', 'All'], ['vulnerability', 'Vulnerabilities'], ['suspicious', 'Suspicious']].map(([k, n]) => (
              <button key={k} className={type === k ? 'active' : ''} onClick={() => setType(k)}>{n}</button>
            ))}
          </div>
        </div>
        <div className="bundles">
          {shown.map((b) => (
            <details key={b.finding_id} className="bundle">
              <summary>
                <Sev level={b.initial_risk.level} />
                <span className="bundle-title">{b.title}</span>
                <span className="muted small">{b.component ? `${b.component.name}@${b.component.version}` : b.category}</span>
              </summary>
              <div className="bundle-body">
                {b.dependency_path.length > 0 && (
                  <div className="small"><b>Dependency path:</b> <span className="mono">{b.dependency_path.join(' → ')}</span></div>
                )}
                <div className="small"><b>Initial risk:</b> {b.initial_risk.rationale}</div>
                {b.fix && <div className="small"><b>Fixed in:</b> <span className="mono">{b.fix}</span></div>}
                <div className="fiu">
                  <div><h3>Verified facts</h3><ul>{b.verified_facts.map((x) => <li key={x}>{x}</li>)}</ul></div>
                  <div><h3>Inference</h3><ul>{b.inference.map((x) => <li key={x}>{x}</li>)}</ul>{!b.inference.length && <p className="muted small">None</p>}</div>
                  <div><h3>Unknown / not checked</h3><ul>{b.unknowns.map((x) => <li key={x}>{x}</li>)}</ul>{!b.unknowns.length && <p className="muted small">None</p>}</div>
                </div>
                <h3>Evidence</h3>
                <ul className="refs">
                  {b.evidence_refs.map((e, i) => (
                    <li key={i}>
                      <span className="chip">{e.kind}</span>{' '}
                      {e.kind === 'advisory' || e.ref.startsWith('http')
                        ? <a className="mono small break" href={e.ref} target="_blank" rel="noreferrer">{e.ref}</a>
                        : e.kind === 'file'
                          ? <a className="mono small" href={fileUrl(e.ref, e.line)} target="_blank" rel="noreferrer">{e.ref}{e.line ? `:${e.line}` : ''}</a>
                          : e.kind === 'sbom'
                            ? <a className="mono small" href={artifactUrl(scanId, e.ref)}>{e.ref}</a>
                            : <span className="mono small">{e.ref}</span>}
                      {e.detail && <span className="muted small"> {e.detail.length > 90 ? e.detail.slice(0, 90) + '…' : e.detail}</span>}
                    </li>
                  ))}
                </ul>
              </div>
            </details>
          ))}
        </div>
      </section>
    </div>
  )
}
