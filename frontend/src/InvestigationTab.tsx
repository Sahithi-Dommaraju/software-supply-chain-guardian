import { Fragment, useState } from 'react'
import type { Results } from './types'
import { AiNote, CodeView, LlmBanner } from './Day2Common'

const VERDICT_CLASS: Record<string, string> = { malicious: 'critical', risky: 'high', harmless: 'low', unknown: 'unrated' }

export default function InvestigationTab({ data }: { data: NonNullable<Results['investigate']> }) {
  const [open, setOpen] = useState<string | null>(null)
  const gd = data.guarddog
  return (
    <div className="day2">
      <LlmBanner llm={data.llm} what="judged each flagged package" />
      <div className="kpis">
        {(['malicious', 'risky', 'harmless', 'unknown'] as const).map((v) => (
          <div key={v} className="kpi"><div className={`kpi-value sev-text ${VERDICT_CLASS[v]}`}>{data.counts[v] ?? 0}</div>
            <div className="kpi-label">{v === 'unknown' ? 'needs review' : v}</div></div>
        ))}
        <div className="kpi"><div className="kpi-value">{data.items.length}</div><div className="kpi-label">Packages investigated</div></div>
      </div>
      <p className="small muted">
        Each package flagged by Suspicious-Change Detection (install script, typosquat lookalike, unexpected origin) or
        listed in OSV as malware is downloaded with <code>npm pack --ignore-scripts</code> (never installed or run),
        compared with the lockfile hash, and its install hooks and the files they run are checked for downloads,
        command execution, obfuscation, secret access and outbound URLs. Deep scan with GuardDog:{' '}
        {gd.status === 'off' ? 'off (set GUARDIAN_GUARDDOG=on in backend/.env to enable)'
          : gd.status === 'ok' ? `${gd.tool} (${gd.seconds}s)` : gd.status === 'cached' ? `${gd.tool} (cached results)`
          : `${gd.status}${gd.reason ? `: ${gd.reason}` : ''}`}.
      </p>
      <section className="card">
        <table className="table">
          <thead><tr><th>Verdict</th><th>Package</th><th>Why flagged</th><th>Tool facts</th><th>Reason</th></tr></thead>
          <tbody>
            {data.items.map((i) => (
              <Fragment key={i.id}>
                <tr className="clickable" onClick={() => setOpen(open === i.id ? null : i.id)}>
                  <td>
                    <span className={`sev ${VERDICT_CLASS[i.verdict]}`}>{i.verdict === 'unknown' ? 'review' : i.verdict}
                      {i.confidence != null && <b>{Math.round(i.confidence * 100)}%</b>}</span>
                    <div className="small muted">{i.basis}</div>
                  </td>
                  <td className="mono small">{i.package}@{i.version}
                    <div>{i.direct ? <span className="chip direct">direct</span> : <span className="chip">transitive</span>}
                      {i.scope !== 'runtime' && <span className="chip">{i.scope}</span>}</div></td>
                  <td>{i.flagged_by.map((f) => <span key={f} className="chip">{f}</span>)}</td>
                  <td className="small">
                    <div>{i.tarball.integrity_match ? '✓ tarball matches lockfile hash' : i.tarball.error ? `✕ ${i.tarball.error}` : '✕ tarball hash differs from lockfile'}</div>
                    <div>{i.install_scripts.length ? i.install_scripts.map((h) => <div key={h.hook} className="mono">{h.hook}: {h.command}</div>) : 'no install hooks'}</div>
                    <div>Static checks: {i.static?.hits.length ? [...new Set(i.static.hits.map((h) => h.rule))].join(', ') : 'no matches'}</div>
                    {i.guarddog.status !== 'off' && <div>GuardDog: {i.guarddog.hits.length ? i.guarddog.hits.map((h) => h.rule).join(', ') : i.guarddog.status === 'ok' ? 'no matches' : i.guarddog.status}</div>}
                    {i.mal_advisories.length > 0 && <div className="note">OSV malware: {i.mal_advisories.join(', ')}</div>}
                  </td>
                  <td className="small">{i.reason}</td>
                </tr>
                {open === i.id && (
                  <tr className="detail-row"><td colSpan={5}>
                    <div className="row-between"><b>Evidence</b><AiNote ai={i.ai} /></div>
                    {i.evidence.length > 0 && <ul className="small">{i.evidence.map((e, n) => <li key={n} className="mono">{e.file}:{e.line} {e.quote && `“${e.quote}”`}</li>)}</ul>}
                    {i.rule_verdict !== i.verdict && <p className="small muted">Rule-only verdict would be: {i.rule_verdict} ({i.rule_reason})</p>}
                    {[...(i.static?.hits ?? []), ...i.guarddog.hits].map((h, n) => <div key={n} className="small"><span className="chip">{h.rule}</span> <span className="mono">{h.file}:{h.line}</span> {h.message}{h.code && <span className="mono muted"> — {h.code}</span>}</div>)}
                    {Object.entries(i.code).map(([file, lines]) => (
                      <CodeView key={file} file={file} lines={file === 'package.json' && i.hook_lines?.length
                        ? lines.slice(Math.max(0, i.hook_lines[0] - 4), i.hook_lines[i.hook_lines.length - 1] + 3) : lines}
                        start={file === 'package.json' && i.hook_lines?.length ? Math.max(1, i.hook_lines[0] - 3) : 1}
                        highlight={[...(file === 'package.json' ? i.hook_lines ?? [] : []), ...i.evidence.filter((e) => e.file === file).map((e) => e.line),
                          ...(i.static?.hits ?? []).filter((h) => h.file === file).map((h) => h.line)]} />
                    ))}
                  </td></tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
        {data.items.length === 0 && <p className="muted">No package needed investigation.</p>}
        {!!data.not_investigated?.length && <p className="small muted">Not investigated (limit of 25 per scan; lower priority):{' '}
          <span className="mono">{data.not_investigated.join(', ')}</span></p>}
      </section>
    </div>
  )
}
