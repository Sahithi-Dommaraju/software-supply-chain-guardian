import { useMemo, useState } from 'react'
import type { Results } from './types'
import { PathChain, Sev } from './Vulnerabilities'

const RULES: Record<string, string> = {
  'install-script': 'Install scripts',
  'unexpected-origin': 'Non-registry origin',
  typosquat: 'Typosquat lookalike',
  'no-lockfile': 'No committed lockfile',
  'unpinned-action': 'Unpinned GitHub Action',
  'base-image': 'Base image not digest-pinned',
  'workflow-risk': 'Risky workflow config',
  'build-install': 'Dockerfile package install',
}

export default function Suspicious({ data, label, repoUrl, sha }: {
  data: NonNullable<Results['change_detection']>; label: (id: string) => string; repoUrl: string; sha: string | null
}) {
  const [rule, setRule] = useState('all')
  const [level, setLevel] = useState('all')
  const rows = useMemo(() => data.findings.filter((f) =>
    (rule === 'all' || f.rule === rule) && (level === 'all' || f.severity === level)), [data, rule, level])
  const src = (file: string, line?: number | null) =>
    `${repoUrl.replace(/\.git$/, '')}/blob/${sha}/${file}${line ? `#L${line}` : ''}`

  return (
    <div className="suspicious">
      <div className="kpis">
        {(['high', 'medium', 'low'] as const).map((l) => (
          <button key={l} className={`kpi kpi-btn ${level === l ? 'on' : ''}`} onClick={() => setLevel(level === l ? 'all' : l)}>
            <div className={`kpi-value sev-text ${l}`}>{data.counts[l]}</div><div className="kpi-label">{l}</div>
          </button>
        ))}
        <div className="kpi"><div className="kpi-value">{Object.keys(data.by_rule).length}</div><div className="kpi-label">Rules triggered</div></div>
      </div>

      <section className="card">
        <h2>Patterns checked</h2>
        <div className="rule-chips">
          <button className={`rule-chip ${rule === 'all' ? 'on' : ''}`} onClick={() => setRule('all')}>All <b>{data.findings.length}</b></button>
          {Object.entries(RULES).map(([k, name]) => (
            <button key={k} className={`rule-chip ${rule === k ? 'on' : ''} ${data.by_rule[k] ? '' : 'zero'}`}
                    onClick={() => setRule(k)} disabled={!data.by_rule[k]}>
              {name} <b>{data.by_rule[k] ?? 0}</b>
            </button>
          ))}
        </div>
        <div className="small muted na">
          Not applicable to a single-commit baseline scan:{' '}
          {data.not_applicable.map((n) => <span key={n.rule} title={n.reason} className="chip">{n.rule}</span>)}
        </div>
      </section>

      <section className="card">
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Severity</th><th>Finding</th><th>Basis</th><th>Evidence</th><th>Why it matters</th></tr></thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id}>
                  <td><Sev level={f.severity} /></td>
                  <td>
                    <div className="small muted">{f.category} · {RULES[f.rule] ?? f.rule}</div>
                    <div>{f.title}</div>
                    {f.path && <div className="small"><PathChain ids={f.path} label={label} /></div>}
                  </td>
                  <td><span className={`chip ${f.status === 'fact' ? 'committed' : 'generated'}`}
                            title={f.status === 'fact' ? 'Read directly from a file or tool output' : 'Heuristic signal: needs human review'}>{f.status}</span></td>
                  <td className="small">
                    {f.evidence.file
                      ? <><a className="mono" href={src(f.evidence.file, f.evidence.line)} target="_blank" rel="noreferrer">
                          {f.evidence.file}{f.evidence.line ? `:${f.evidence.line}` : ''}</a>
                          {f.evidence.text && <div className="code">{f.evidence.text}</div>}</>
                      : <><div>{f.evidence.source}{f.evidence.field && `: ${f.evidence.field}`}</div>
                          {f.evidence.resolved && <div className="mono muted break">{f.evidence.resolved}</div>}
                          {f.evidence.lookalike_of && <div>lookalike of <b className="mono">{f.evidence.lookalike_of}</b></div>}</>}
                  </td>
                  <td className="small">{f.rationale}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
