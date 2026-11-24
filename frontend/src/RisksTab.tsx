import { Fragment, useState } from 'react'
import type { Results } from './types'
import { AiNote, LlmBanner, Snippets } from './Day2Common'

const REACH = { reachable: 'Reachable', unknown: 'Unknown', not_reachable: 'Not reachable' } as const
const FACTOR_HELP: Record<string, string> = {
  U: 'Usage: production 1.0, dev-only 0.5', D: 'Depth: direct 1.0, transitive 0.8',
  P: 'Platform: optional or OS/CPU-restricted 0.6, else 1.0', E: 'Exploitation: CISA KEV or EPSS ≥ 0.1 → 1.3, else 1.0',
  R: 'Reachability: Reachable 1.0, Unknown 1.0, Not reachable 0.7 (never lowers critical, KEV or malware)',
}

export default function RisksTab({ data }: { data: NonNullable<Results['prioritize']> }) {
  const [open, setOpen] = useState<string | null>(null)
  const [bandF, setBandF] = useState('all')
  const rows = data.risks.filter((r) => bandF === 'all' || r.band === bandF)
  const f = data.feeds
  return (
    <div className="day2">
      <LlmBanner llm={data.llm} what="labelled reachability for production high/medium packages" />
      <div className="kpis">
        {(['critical', 'high', 'medium', 'low'] as const).map((b) => (
          <button key={b} className={`kpi kpi-btn ${bandF === b ? 'on' : ''}`} onClick={() => setBandF(bandF === b ? 'all' : b)}>
            <div className={`kpi-value sev-text ${b}`}>{data.counts[b] ?? 0}</div><div className="kpi-label">{b}</div>
          </button>
        ))}
        {(['reachable', 'unknown', 'not_reachable'] as const).map((k) => (
          <div key={k} className="kpi"><div className="kpi-value">{data.reachability[k] ?? 0}</div><div className="kpi-label">{REACH[k]}</div></div>
        ))}
      </div>
      <section className="card formula">
        <div><b>score = min(10, CVSS × U × D × P × E × R)</b> · bands: critical ≥ 9, high ≥ 7, medium ≥ 4, low &lt; 4 · order: band, then Reachable → Unknown → Not reachable, then score</div>
        <div className="small muted">
          CISA KEV: {f.kev.status === 'ok' ? `catalog ${f.kev.catalog_version} (${f.kev.entries} CVEs)` : `unavailable (${f.kev.reason})`} ·
          EPSS: {f.epss.status === 'ok' ? `${f.epss.cves_scored} CVEs scored` : `unavailable (${f.epss.reason})`}
        </div>
      </section>
      <section className="card">
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>#</th><th>Score</th><th>Package</th><th>Reachability</th><th>Formula</th><th>Signals</th><th>Advisories</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <Fragment key={r.id}>
                  <tr className="clickable" onClick={() => setOpen(open === r.id ? null : r.id)}>
                    <td>{r.rank}</td>
                    <td><span className={`sev ${r.band}`}>{r.band}<b>{r.final_score.toFixed(1)}</b></span>
                      <div className="small muted">{r.confidence} confidence</div></td>
                    <td className="mono small">{r.version ? `${r.package}@${r.version}` : r.package}
                      <div>{r.direct ? <span className="chip direct">direct</span> : <span className="chip" title={r.path.join(' → ')}>via {r.controlled_by}</span>}
                        {r.scope !== 'runtime' && <span className="chip">{r.scope}</span>}</div></td>
                    <td><span className={`reach ${r.reachability}`}>{REACH[r.reachability]}</span>
                      <div className="small muted">{r.reachability_basis}</div></td>
                    <td className="mono small">{r.formula}
                      <div>{Object.entries(r.factors).map(([k, v]) => <span key={k} className="chip" title={FACTOR_HELP[k]}>{k} {v}</span>)}</div></td>
                    <td className="small">
                      {r.kev.length > 0 && <div className="note">CISA KEV: {r.kev.join(', ')}</div>}
                      <div>EPSS {r.epss != null ? `${(r.epss * 100).toFixed(1)}%` : 'n/a'}</div>
                      {r.labels.map((l) => <span key={l} className="chip generated">{l}</span>)}
                    </td>
                    <td className="mono small">{r.advisories.slice(0, 3).map((a) => <div key={a.id}>{a.id}</div>)}
                      {r.advisories.length > 3 && <div className="muted">+{r.advisories.length - 3} more</div>}</td>
                  </tr>
                  {open === r.id && (
                    <tr className="detail-row"><td colSpan={7}>
                      <div className="row-between"><b>Why this rank</b><AiNote ai={r.ai} /></div>
                      <p className="small">CVSS {r.cvss} ({r.cvss_source}). {r.reason ?? ''}</p>
                      <p className="small mono">{r.path.join(' → ')}</p>
                      {r.evidence.length > 0 && <ul className="small">{r.evidence.map((e, n) => <li key={n} className="mono">{e.file}:{e.line} {e.code && `— ${e.code.trim()}`}</li>)}</ul>}
                      <Snippets snippets={r.usage_snippets} cites={r.evidence} />
                      <table className="table compact">
                        <thead><tr><th>Advisory</th><th>CVSS</th><th>Fixed in</th><th>Title</th></tr></thead>
                        <tbody>{r.advisories.map((a) => (
                          <tr key={a.id}><td className="mono small"><a href={a.url} target="_blank" rel="noreferrer">{a.id}</a> {a.cves.join(' ')}</td>
                            <td>{a.cvss ?? a.severity}</td><td className="mono small">{a.fix ?? 'no fix'}</td><td className="small">{a.title}</td></tr>
                        ))}</tbody>
                      </table>
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
