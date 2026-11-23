import { useMemo, useState } from 'react'
import type { Results } from './types'
import { artifactUrl } from './types'

const PAGE = 100

export default function SbomTable({ scanId, sbom, discovery, paths }: {
  scanId: string
  sbom: NonNullable<Results['sbom']>
  discovery: NonNullable<Results['discovery']>
  paths?: Record<string, string[]>
}) {
  const [q, setQ] = useState('')
  const [scope, setScope] = useState('all')
  const [kind, setKind] = useState('all')
  const [page, setPage] = useState(0)

  const names = useMemo(() => new Map([
    ...discovery.components.map((c) => [c.id, `${c.name}@${c.version}`] as const),
    ...discovery.projects.map((p) => [p.id, p.name ?? p.path] as const),
  ]), [discovery])

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return discovery.components.filter((c) =>
      (!needle || c.purl.toLowerCase().includes(needle) || (c.license ?? '').toLowerCase().includes(needle)) &&
      (scope === 'all' || c.scope === scope) &&
      (kind === 'all' || (kind === 'direct') === c.direct) &&
      (kind !== 'scripts' || c.install_script))
  }, [discovery, q, scope, kind])
  const pages = Math.max(1, Math.ceil(rows.length / PAGE))
  const shown = rows.slice(page * PAGE, page * PAGE + PAGE)
  const via = (id: string) => {
    const p = paths?.[id]
    return p && p.length > 3 ? names.get(p[p.length - 2]) : p ? 'project root' : '—'
  }

  return (
    <div className="sbom">
      <section className="card sbom-head">
        <div>
          <div className="eyebrow">Software Bill of Materials</div>
          <h2>{sbom.format} {sbom.spec_version} · {sbom.components} components · {sbom.dependency_entries} dependency entries</h2>
          <div className="mono muted small">{sbom.serial_number} · sha256 {sbom.sha256.slice(0, 24)}… · {(sbom.size_bytes / 1024).toFixed(0)} KB</div>
        </div>
        <a className="button" href={artifactUrl(scanId, sbom.artifact)}>Download SBOM (JSON)</a>
      </section>

      <section className="card">
        <h3>Independent cross-check</h3>
        <table className="table compact">
          <thead><tr><th>Project</th><th>Tool</th><th>Guardian count</th><th>Tool count</th><th>Result</th></tr></thead>
          <tbody>
            {sbom.crosschecks.map((c) => (
              <tr key={c.project}>
                <td>{c.project === 'project:.' ? '(repo root)' : c.project.replace('project:', '')}</td>
                <td>{c.tool}</td>
                <td>{c.ours}</td>
                <td>{c.tool_count ?? '—'}</td>
                <td>
                  {c.status === 'ok'
                    ? <span className={`badge ${c.tool_count === c.ours ? 'done' : 'partial'}`}>{c.tool_count === c.ours ? 'match' : 'differs'}</span>
                    : <span className="badge failed" title={c.error}>tool failed</span>}
                  {c.artifact && <a className="small" href={artifactUrl(scanId, c.artifact)}> raw</a>}
                </td>
              </tr>
            ))}
            {sbom.crosschecks.length === 0 && <tr><td colSpan={5} className="muted">No npm projects to cross-check.</td></tr>}
          </tbody>
        </table>
      </section>

      <section className="card">
        <div className="filters">
          <input placeholder="Filter by name, purl or license" value={q} onChange={(e) => { setQ(e.target.value); setPage(0) }} aria-label="Filter components" />
          <select value={kind} onChange={(e) => { setKind(e.target.value); setPage(0) }} aria-label="Relationship">
            <option value="all">Direct + transitive</option>
            <option value="direct">Direct only</option>
            <option value="transitive">Transitive only</option>
            <option value="scripts">Has install script</option>
          </select>
          <select value={scope} onChange={(e) => { setScope(e.target.value); setPage(0) }} aria-label="Scope">
            <option value="all">All scopes</option>
            <option value="runtime">Runtime</option>
            <option value="dev">Dev</option>
            <option value="optional">Optional</option>
          </select>
          <span className="muted small">{rows.length} of {discovery.components.length}</span>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Relationship</th><th>Introduced via</th><th>Scope</th><th>License</th><th>Origin</th></tr></thead>
            <tbody>
              {shown.map((c) => (
                <tr key={c.id}>
                  <td className="mono" title={c.purl}>{c.name}{c.install_script && <span className="chip generated" title="Runs an install script">script</span>}</td>
                  <td className="mono">{c.version}</td>
                  <td>{c.ecosystem}</td>
                  <td>{c.direct ? <span className="chip direct">direct</span> : <span className="chip">transitive</span>}</td>
                  <td className="mono small" title={paths?.[c.id]?.map((p) => names.get(p) ?? p).join(' → ')}>{via(c.id)}</td>
                  <td>{c.scope}</td>
                  <td>{c.license ?? <span className="muted">unknown</span>}</td>
                  <td className="small">{c.origin}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="pager">
          <button disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <span>Page {page + 1} of {pages}</span>
          <button disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      </section>
    </div>
  )
}
