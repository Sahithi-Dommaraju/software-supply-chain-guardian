import { Fragment, useMemo, useState } from 'react'
import type { Results, VulnFinding } from './types'
import { artifactUrl } from './types'

export function Sev({ level, score }: { level: string; score?: number | null }) {
  return <span className={`sev ${level}`}>{level}{score != null && <b>{score.toFixed(1)}</b>}</span>
}

export function PathChain({ ids, label }: { ids: string[] | null | undefined; label: (id: string) => string }) {
  if (!ids?.length) return <span className="muted">—</span>
  const steps = ids.slice(1) // drop the repo node
  return (
    <span className="chain">
      {steps.map((id, i) => (
        <Fragment key={id}>
          {i > 0 && <span className="arrow">→</span>}
          <span className={i === steps.length - 1 ? 'last' : ''}>{label(id)}</span>
        </Fragment>
      ))}
    </span>
  )
}

const LEVELS = ['critical', 'high', 'medium', 'low', 'unrated'] as const

export default function Vulnerabilities({ scanId, data, label }: {
  scanId: string; data: NonNullable<Results['vulnerability']>; label: (id: string) => string
}) {
  const [level, setLevel] = useState('all')
  const [rel, setRel] = useState('all')
  const [q, setQ] = useState('')
  const [open, setOpen] = useState<string | null>(null)

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return data.findings.filter((f) =>
      (level === 'all' || f.severity === level) &&
      (rel === 'all' || (rel === 'direct' && f.direct) || (rel === 'transitive' && !f.direct) ||
        (rel === 'runtime' && f.scope === 'runtime')) &&
      (!needle || `${f.name} ${f.advisory_id} ${f.aliases.join(' ')} ${f.title}`.toLowerCase().includes(needle)))
  }, [data, level, rel, q])

  return (
    <div className="vulns">
      <div className="kpis">
        {LEVELS.map((l) => (
          <button key={l} className={`kpi kpi-btn ${level === l ? 'on' : ''}`} onClick={() => setLevel(level === l ? 'all' : l)}>
            <div className={`kpi-value sev-text ${l}`}>{data.counts[l]}</div>
            <div className="kpi-label">{l}</div>
          </button>
        ))}
        <div className="kpi"><div className="kpi-value">{data.packages_affected}</div><div className="kpi-label">Packages affected</div></div>
      </div>

      <section className="card">
        <h2>Scan evidence</h2>
        <table className="table compact">
          <thead><tr><th>Project</th><th>Tool</th><th>Target</th><th>Result</th><th>Trivy cross-check</th></tr></thead>
          <tbody>
            {data.scans.map((s) => (
              <tr key={s.project}>
                <td>{label(s.project)}</td>
                <td className="small">
                  {s.tool_version ? <>osv-scanner {s.tool_version}<div className="muted">{s.mode}</div><div className="muted">{s.scanned_at}</div></> : '—'}
                  {s.command && <div className="mono muted">{s.command}</div>}
                </td>
                <td className="small">
                  <span className="mono">{s.target ?? s.manifest}</span>
                  {s.target_sha256 && <div className="mono muted">sha256 {s.target_sha256.slice(0, 16)}…</div>}
                </td>
                <td>
                  <span className={`badge ${s.status === 'ok' ? 'done' : 'failed'}`}>{s.status}</span>
                  {s.status === 'ok' && <div className="small">{s.findings} advisories on {s.packages_affected} packages</div>}
                  {(s.error || s.reason) && <div className="small note">{s.error ?? s.reason}</div>}
                  {s.artifact && <a className="small" href={artifactUrl(scanId, s.artifact)}>raw OSV JSON</a>}
                </td>
                <td className="small">
                  {!s.trivy ? <span className="muted">Trivy not installed</span>
                    : s.trivy.status !== 'ok' ? <span className="note">failed: {s.trivy.error}</span>
                    : <>
                        Trivy {s.trivy.version}: {s.trivy.matched_osv} of {s.trivy.trivy_entries} entries match OSV
                        {!!s.trivy.only_trivy?.length && <div className="muted" title={s.trivy.only_trivy.join('\n')}>
                          {s.trivy.only_trivy.length} only in Trivy (legacy IDs, hover)</div>}
                        {s.trivy.artifact && <div><a href={artifactUrl(scanId, s.trivy.artifact)}>raw Trivy JSON</a></div>}
                      </>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <div className="filters">
          <input placeholder="Filter by package, GHSA/CVE id or title" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter advisories" />
          <select value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Severity">
            <option value="all">All severities</option>
            {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
          <select value={rel} onChange={(e) => setRel(e.target.value)} aria-label="Relationship">
            <option value="all">Direct + transitive</option>
            <option value="direct">Direct only</option>
            <option value="transitive">Transitive only</option>
            <option value="runtime">Runtime scope only</option>
          </select>
          <span className="muted small">{rows.length} of {data.findings.length}</span>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Severity</th><th>Advisory</th><th>Package</th><th>Introduced via</th><th>Fixed in</th><th>Summary</th></tr></thead>
            <tbody>
              {rows.map((f: VulnFinding) => (
                <Fragment key={f.id}>
                  <tr className="clickable" onClick={() => setOpen(open === f.id ? null : f.id)}>
                    <td><Sev level={f.severity} score={f.cvss_score} /></td>
                    <td className="mono small">
                      <a href={f.url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>{f.advisory_id}</a>
                      {f.cves.map((c) => <div key={c} className="muted">{c}</div>)}
                    </td>
                    <td className="mono small">
                      {f.name}@{f.version}
                      <div>{f.direct ? <span className="chip direct">direct</span> : <span className="chip">transitive</span>}
                        {f.scope && f.scope !== 'runtime' && <span className="chip">{f.scope}</span>}</div>
                    </td>
                    <td className="small"><PathChain ids={f.path} label={label} /></td>
                    <td className="mono small">{f.fix ?? <span className="note">no fix</span>}</td>
                    <td className="small">{f.title}</td>
                  </tr>
                  {open === f.id && (
                    <tr className="detail-row">
                      <td colSpan={6}>
                        <dl className="facts">
                          <dt>Severity source</dt><dd>{f.severity_source}{f.advisory_label && ` (advisory label: ${f.advisory_label})`}</dd>
                          {f.cvss_vector && <><dt>CVSS vector</dt><dd className="mono small">{f.cvss_vector}</dd></>}
                          <dt>All IDs</dt><dd className="mono small">{[f.advisory_id, ...f.aliases].join(', ')}</dd>
                          {f.cwe.length > 0 && <><dt>Weakness</dt><dd>{f.cwe.join(', ')}</dd></>}
                          <dt>Fixed versions</dt><dd className="mono small">{f.fixed_versions.join(', ') || 'none published'}</dd>
                          <dt>Project</dt><dd>{[f.project, ...(f.also_in ?? [])].map(label).join(', ')}</dd>
                          <dt>Trivy</dt><dd>{f.trivy_confirmed ? 'also reports this advisory' : 'not reported by Trivy (or Trivy not run)'}</dd>
                          {f.published && <><dt>Published</dt><dd>{f.published.slice(0, 10)}</dd></>}
                        </dl>
                      </td>
                    </tr>
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
