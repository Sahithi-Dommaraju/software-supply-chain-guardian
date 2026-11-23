import { useEffect, useState } from 'react'
import type { Scan, ScanSummary } from './types'
import { AgentPipeline, Overview } from './Overview'
import GraphView, { type Theme } from './GraphView'
import SbomTable from './SbomTable'
import Inspection from './Inspection'

const TABS = [
  ['overview', 'Overview'],
  ['graph', 'Dependency graph'],
  ['sbom', 'SBOM'],
  ['inspection', 'Container & CI/CD'],
  ['vulnerability', 'Vulnerabilities'],
  ['change_detection', 'Suspicious changes'],
  ['evidence', 'Evidence report'],
] as const
type Tab = (typeof TABS)[number][0]

const PLANNED: Record<string, string> = {
  vulnerability: 'Matches every SBOM component against OSV / GitHub advisories (OSV-Scanner or Trivy) and shows advisory ID, severity, affected range and fixed version.',
  change_detection: 'Flags non-CVE supply-chain risks: unexpected or typosquatted dependencies, install scripts, modified lockfiles, unpinned images and CI actions, with diff evidence.',
  evidence: 'Correlates both detection branches with the dependency graph into evidence bundles: verified facts, inference and unknowns, plus the Day 1 report.',
}

const shortRepo = (url: string) => url.replace('https://github.com/', '')
const when = (t: number) => new Date(t * 1000).toLocaleString()

function useHashRoute(): [string | null, (id: string | null) => void] {
  const read = () => location.hash.match(/^#\/scan\/(\w+)/)?.[1] ?? null
  const [id, setId] = useState(read)
  useEffect(() => {
    const on = () => setId(read())
    addEventListener('hashchange', on)
    return () => removeEventListener('hashchange', on)
  }, [])
  return [id, (next) => { location.hash = next ? `/scan/${next}` : '' }]
}

function useTheme() {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const saved = localStorage.getItem('theme')
      if (saved === 'light' || saved === 'dark') return saved
    } catch { /* storage blocked: fall back to OS preference */ }
    return matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  })
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('theme', theme) } catch { /* not persisted */ }
  }, [theme])
  return [theme, setTheme] as const
}

export default function App() {
  const [scanId, go] = useHashRoute()
  const [theme, setTheme] = useTheme()
  return (
    <div className="app">
      <header className="topbar">
        <a className="brand" href="#" onClick={() => go(null)}>
          <span className="logo">◆</span> Supply Chain Guardian
        </a>
        <span className="topbar-sub">Agentic software supply-chain analysis</span>
        <button className="theme-toggle" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}>
          {theme === 'dark' ? '☀ Light' : '☾ Dark'}
        </button>
      </header>
      <main>{scanId ? <ScanPage id={scanId} theme={theme} /> : <Home onScan={go} />}</main>
    </div>
  )
}

function Home({ onScan }: { onScan: (id: string) => void }) {
  const [url, setUrl] = useState('https://github.com/juice-shop/juice-shop')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [scans, setScans] = useState<ScanSummary[]>([])
  useEffect(() => { fetch('/api/scans').then((r) => r.json()).then(setScans).catch(() => {}) }, [])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    const r = await fetch('/api/scans', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ repo_url: url }),
    }).catch(() => null)
    setBusy(false)
    if (!r) return setError('Backend not reachable on port 8000')
    const body = await r.json()
    if (!r.ok) return setError(body.detail ?? 'Scan request failed')
    onScan(body.id)
  }

  return (
    <div className="home">
      <section className="hero">
        <h1>Scan a repository's software supply chain</h1>
        <p>
          Paste a public GitHub repository. The Guardian clones it at a pinned commit, discovers every direct and
          transitive dependency, generates a CycloneDX SBOM, maps the dependency graph and inspects containers and
          CI/CD. No repository code is executed.
        </p>
        <form className="scan-form" onSubmit={submit}>
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/owner/repo"
                 aria-label="GitHub repository URL" spellCheck={false} />
          <button disabled={busy}>{busy ? 'Starting…' : 'Start scan'}</button>
        </form>
        {error && <div className="form-error">{error}</div>}
      </section>
      {scans.length > 0 && (
        <section className="card">
          <h2>Recent scans</h2>
          <table className="table">
            <thead><tr><th>Repository</th><th>Commit</th><th>Status</th><th>Started</th></tr></thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="clickable" onClick={() => onScan(s.id)}>
                  <td>{shortRepo(s.repo_url)}</td>
                  <td className="mono">{s.commit_sha?.slice(0, 12) ?? '—'}</td>
                  <td><span className={`badge ${s.status}`}>{s.status}</span></td>
                  <td>{when(s.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  )
}

function ScanPage({ id, theme }: { id: string; theme: Theme }) {
  const [scan, setScan] = useState<Scan | null>(null)
  const [missing, setMissing] = useState(false)
  const [tab, setTab] = useState<Tab>('overview')

  useEffect(() => {
    let timer = 0
    const load = async () => {
      const r = await fetch(`/api/scans/${id}`).catch(() => null)
      if (r?.status === 404) return setMissing(true)
      if (r?.ok) {
        const s: Scan = await r.json()
        setScan(s)
        if (s.status === 'completed' || s.status === 'failed') return
      }
      timer = window.setTimeout(load, 2000)
    }
    load()
    return () => clearTimeout(timer)
  }, [id])

  if (missing) return <div className="card">Scan not found.</div>
  if (!scan) return <div className="card">Loading…</div>
  const co = scan.results.checkout

  return (
    <div className="scan">
      <section className="scan-head card">
        <div>
          <div className="eyebrow">Repository</div>
          <h1><a href={scan.repo_url} target="_blank" rel="noreferrer">{shortRepo(scan.repo_url)}</a></h1>
          {co && (
            <div className="meta">
              <span>branch <b>{co.branch}</b></span>
              <span>commit <b className="mono">{co.commit_sha.slice(0, 12)}</b></span>
              <span>{new Date(co.commit_date).toLocaleDateString()} · {co.commit_author}</span>
              <span className="subject">“{co.commit_subject}”</span>
            </div>
          )}
        </div>
        <span className={`badge big ${scan.status}`}>{scan.status}</span>
      </section>
      {scan.error && <div className="alert">Scan failed: {scan.error}. Results below are incomplete; nothing here means “clean”.</div>}

      <AgentPipeline agents={scan.agents} onPick={(k) => TABS.some(([t]) => t === k) && setTab(k as Tab)} />

      <nav className="tabs">
        {TABS.map(([key, label]) => (
          <button key={key} className={tab === key ? 'active' : ''} onClick={() => setTab(key)}>
            {label}
            {scan.agents[key]?.status === 'planned' && <span className="soon">planned</span>}
          </button>
        ))}
      </nav>

      <div className="tab-body">
        {tab === 'overview' && <Overview scan={scan} />}
        {tab === 'graph' && (scan.results.graph && scan.results.discovery
          ? <GraphView graph={scan.results.graph} components={scan.results.discovery.components} theme={theme} />
          : <Waiting agent={scan.agents.graph} />)}
        {tab === 'sbom' && (scan.results.sbom && scan.results.discovery
          ? <SbomTable scanId={scan.id} sbom={scan.results.sbom} discovery={scan.results.discovery} paths={scan.results.graph?.paths} />
          : <Waiting agent={scan.agents.sbom} />)}
        {tab === 'inspection' && (scan.results.inspection
          ? <Inspection data={scan.results.inspection} repoUrl={scan.repo_url} sha={scan.commit_sha} />
          : <Waiting agent={scan.agents.inspection} />)}
        {tab in PLANNED && (
          <div className="card planned-panel">
            <div className="eyebrow">{scan.agents[tab].name} · planned</div>
            <h2>Not built yet</h2>
            <p>{PLANNED[tab]}</p>
            <p className="muted">This agent plugs into the same pipeline after the Container & CI/CD step. Until it runs, this
              scan makes no claim about {tab === 'vulnerability' ? 'known vulnerabilities' : 'these risks'}.</p>
          </div>
        )}
      </div>
    </div>
  )
}

function Waiting({ agent }: { agent: Scan['agents'][string] }) {
  const msg = agent.status === 'failed' ? `Failed: ${agent.error}`
    : agent.status === 'skipped' ? 'Skipped because an earlier agent failed.'
    : `${agent.name} is ${agent.status}…`
  return <div className="card muted">{msg}</div>
}
