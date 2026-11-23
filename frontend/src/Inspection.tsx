import { useState } from 'react'
import type { Results } from './types'

export default function Inspection({ data, repoUrl, sha }: {
  data: NonNullable<Results['inspection']>; repoUrl: string; sha: string | null
}) {
  const [onlyUnpinned, setOnlyUnpinned] = useState(true)
  const src = (file: string, line: number | null) =>
    `${repoUrl.replace(/\.git$/, '')}/blob/${sha}/${file}${line ? `#L${line}` : ''}`
  const actions = data.workflows.flatMap((w) => w.actions.map((a) => ({ ...a, file: w.file })))
    .filter((a) => !onlyUnpinned || !a.pinned)
  const s = data.stats

  return (
    <div className="inspection">
      <div className="kpis">
        <div className="kpi"><div className="kpi-value">{s.dockerfiles}</div><div className="kpi-label">Dockerfiles</div></div>
        <div className="kpi"><div className="kpi-value">{s.base_images}</div><div className="kpi-label">Base images</div></div>
        <div className="kpi"><div className="kpi-value">{s.workflows}</div><div className="kpi-label">Workflows</div></div>
        <div className="kpi"><div className="kpi-value">{s.actions}</div><div className="kpi-label">Action references</div></div>
        <div className="kpi"><div className="kpi-value">{s.unpinned_actions}</div><div className="kpi-label">Not SHA-pinned</div></div>
        <div className="kpi"><div className="kpi-value">{s.warnings}</div><div className="kpi-label">Warnings</div></div>
      </div>

      {data.not_inspected.length > 0 && (
        <div className="alert">Other CI systems found but not inspected: {data.not_inspected.join(', ')}</div>
      )}

      <section className="card">
        <h2>Observations</h2>
        <p className="muted small">Static facts with file and line. Scoring them as findings is the Suspicious-Change Detection agent's job.</p>
        <table className="table">
          <thead><tr><th>Level</th><th>Observation</th><th>Evidence</th></tr></thead>
          <tbody>
            {data.observations.map((o, i) => (
              <tr key={i}>
                <td><span className={`level ${o.level}`}>{o.level}</span></td>
                <td>{o.message}</td>
                <td>
                  <a className="mono small" href={src(o.file, o.line)} target="_blank" rel="noreferrer">{o.file}{o.line ? `:${o.line}` : ''}</a>
                  {o.text && <div className="code">{o.text}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <div className="two-col">
        <section className="card">
          <h2>Container base images</h2>
          {data.dockerfiles.length === 0 && <p className="muted">No Dockerfile found.</p>}
          {data.dockerfiles.map((d) => (
            <div key={d.file} className="docker">
              <a className="mono" href={src(d.file, null)} target="_blank" rel="noreferrer">{d.file}</a>
              <ul>
                {d.images.map((im) => (
                  <li key={im.line}>
                    <span className="mono">{im.image}</span>{im.stage && <span className="muted"> as {im.stage}</span>}
                    <span className={`level ${im.level}`}>{im.pinning}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </section>

        <section className="card">
          <div className="row-between">
            <h2>GitHub Actions</h2>
            <label className="small"><input type="checkbox" checked={onlyUnpinned} onChange={(e) => setOnlyUnpinned(e.target.checked)} /> only not SHA-pinned</label>
          </div>
          <div className="table-wrap short">
            <table className="table compact">
              <thead><tr><th>Action</th><th>Workflow</th><th>Pinned</th></tr></thead>
              <tbody>
                {actions.map((a) => (
                  <tr key={a.file + a.line}>
                    <td className="mono small break">{a.uses}</td>
                    <td><a className="small" href={src(a.file, a.line)} target="_blank" rel="noreferrer">{a.file.replace('.github/workflows/', '')}:{a.line}</a></td>
                    <td>{a.pinned ? '✓ SHA' : <span className={`level ${a.first_party ? 'notice' : 'warning'}`}>tag</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  )
}
