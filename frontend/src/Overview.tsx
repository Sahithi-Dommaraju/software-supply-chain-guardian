import type { Agent, Scan } from './types'
import { artifactUrl } from './types'

const ICON: Record<string, string> = {
  pending: '○', running: '◌', done: '✓', partial: '!', failed: '✕', skipped: '–', planned: '…',
}

export function AgentPipeline({ agents, onPick }: { agents: Record<string, Agent>; onPick: (key: string) => void }) {
  return (
    <section className="pipeline">
      {Object.entries(agents).map(([key, a], i) => (
        <button key={key} className={`agent ${a.status}`} onClick={() => onPick(key)} title={a.error ?? a.summary ?? ''}>
          <div className="agent-top">
            <span className="agent-icon">{ICON[a.status]}</span>
            <span className="agent-step">{i + 1}</span>
          </div>
          <div className="agent-name">{a.name}</div>
          <div className="agent-sum">
            {a.status === 'running' ? 'Running…' : a.error ?? a.summary ?? a.status}
          </div>
          {a.duration != null && <div className="agent-time">{a.duration.toFixed(1)}s</div>}
        </button>
      ))}
    </section>
  )
}

function Kpi({ label, value, hint }: { label: string; value: number | string | undefined; hint?: string }) {
  return (
    <div className="kpi">
      <div className="kpi-value">{value ?? '—'}</div>
      <div className="kpi-label">{label}</div>
      {hint && <div className="kpi-hint">{hint}</div>}
    </div>
  )
}

export function Overview({ scan }: { scan: Scan }) {
  const { discovery: d, graph: g, sbom, inspection: ins, checkout, vulnerability: v, change_detection: cd } = scan.results
  const hist = g ? Object.entries(g.stats.depth_histogram) : []
  const maxBar = Math.max(1, ...hist.map(([, n]) => n))
  const label = (id: string) => g?.nodes.find((n) => n.id === id)?.label ?? id

  return (
    <div className="overview">
      <div className="kpis">
        <Kpi label="Components" value={d?.stats.components} />
        <Kpi label="Direct" value={d?.stats.direct} />
        <Kpi label="Transitive" value={d?.stats.transitive} />
        <Kpi label="Dependency edges" value={d?.stats.edges} />
        <Kpi label="Max depth" value={g?.stats.max_depth} />
        <Kpi label="Install scripts" value={d?.stats.install_scripts} hint="packages that run code on install" />
        <Kpi label="CI/container warnings" value={ins?.stats.warnings} />
        <Kpi label="SBOM" value={sbom ? `CDX ${sbom.spec_version}` : undefined} />
        <Kpi label="Critical / high advisories" value={v ? `${v.counts.critical} / ${v.counts.high}` : undefined} hint={v ? `${v.findings.length} advisories on ${v.packages_affected} packages` : undefined} />
        <Kpi label="Suspicious-pattern findings" value={cd?.findings.length} hint={cd ? `${cd.counts.high} high, ${cd.counts.medium} medium` : undefined} />
      </div>

      {d && (
        <section className="card">
          <h2>Discovered projects</h2>
          <table className="table">
            <thead><tr><th>Manifest</th><th>Ecosystem</th><th>Lockfile</th><th>Components</th><th>Status</th><th>Evidence</th></tr></thead>
            <tbody>
              {d.projects.map((p) => (
                <tr key={p.id}>
                  <td className="mono">{p.manifest}{p.name && <div className="muted small">{p.name} {p.version}</div>}</td>
                  <td>{p.ecosystem}</td>
                  <td>
                    {p.lockfile ?? 'none'}
                    {p.lock_source && <span className={`chip ${p.lock_source}`}>{p.lock_source}</span>}
                  </td>
                  <td>{p.component_count}{p.declared_direct != null && <div className="muted small">{p.declared_direct} declared direct</div>}</td>
                  <td><span className={`badge ${p.status}`}>{p.status}</span></td>
                  <td className="small">
                    {p.evidence.command && <div className="mono">{p.evidence.command}</div>}
                    {p.evidence.generated_at && <div>npm {p.evidence.npm_version} · resolved {p.evidence.generated_at}</div>}
                    {p.evidence.sha256 && <div className="mono muted">sha256 {p.evidence.sha256.slice(0, 16)}…</div>}
                    {p.evidence.artifact && <a href={artifactUrl(scan.id, p.evidence.artifact)}>download lockfile</a>}
                    {p.notes.map((n) => <div key={n} className="note">{n}</div>)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {d && (d.warnings.length > 0 || d.unsupported.length > 0) && (
        <section className="card warn-card">
          <h2>Coverage gaps</h2>
          <ul>{d.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </section>
      )}

      <div className="two-col">
        {g && (
          <section className="card">
            <h2>Components by dependency depth</h2>
            <div className="bars">
              {hist.map(([depth, n]) => (
                <div className="bar-row" key={depth}>
                  <span className="bar-label">{depth === '1' ? 'direct' : `depth ${depth}`}</span>
                  <span className="bar"><span style={{ width: `${(100 * n) / maxBar}%` }} /></span>
                  <span className="bar-val">{n}</span>
                </div>
              ))}
            </div>
          </section>
        )}
        {g && (
          <section className="card">
            <h2>Most depended-on packages</h2>
            <ol className="ranked">
              {g.most_depended_on.map((m) => (
                <li key={m.id}><span className="mono">{label(m.id)}</span><span className="muted">{m.dependents} dependents</span></li>
              ))}
            </ol>
          </section>
        )}
      </div>

      {checkout && (
        <section className="card">
          <h2>Scan provenance</h2>
          <dl className="facts">
            <dt>Repository</dt><dd>{checkout.url}</dd>
            <dt>Pinned commit</dt><dd className="mono">{checkout.commit_sha}</dd>
            <dt>Checkout</dt><dd className="mono">{checkout.clone}</dd>
            <dt>Tracked files</dt><dd>{checkout.tracked_files}</dd>
            {sbom && <><dt>SBOM sha256</dt><dd className="mono">{sbom.sha256}</dd></>}
            <dt>Execution policy</dt><dd>No repository scripts run; lockfiles resolved with --ignore-scripts</dd>
          </dl>
        </section>
      )}
    </div>
  )
}
