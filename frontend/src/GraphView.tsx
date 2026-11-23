import { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import type { Component, GraphEdge, GraphNode, Results } from './types'

type G = NonNullable<Results['graph']>
type View = 'all' | 'runtime' | 'direct'
type FNode = GraphNode & { x?: number; y?: number; installScript?: boolean }
type FLink = { source: string | FNode; target: string | FNode; kind: string }

const COLORS = {
  repo: '#f8fafc', project: '#a78bfa', direct: '#2dd4bf', transitive: '#60a5fa', dev: '#475569',
  path: '#facc15', script: '#fb923c',
}
const idOf = (x: string | FNode) => (typeof x === 'string' ? x : x.id)

function nodeColor(n: FNode) {
  if (n.type === 'repo') return COLORS.repo
  if (n.type === 'project') return COLORS.project
  if (n.scope === 'dev') return COLORS.dev
  return n.direct ? COLORS.direct : COLORS.transitive
}

export default function GraphView({ graph, components }: { graph: G; components: Component[] }) {
  const wrap = useRef<HTMLDivElement>(null)
  const fg = useRef<any>(null)
  const fitted = useRef(false)
  const [size, setSize] = useState({ w: 800, h: 600 })
  const [view, setView] = useState<View>('all')
  const [selected, setSelected] = useState<string | null>(null)
  const [query, setQuery] = useState('')

  const byId = useMemo(() => new Map(components.map((c) => [c.id, c])), [components])
  const labelToId = useMemo(() => new Map(graph.nodes.map((n) => [n.label, n.id])), [graph])

  useEffect(() => {
    const el = wrap.current!
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight }))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // Fresh copies: the force engine mutates nodes/links in place.
  const data = useMemo(() => {
    const keep = (n: GraphNode) =>
      n.type !== 'component' || view === 'all' || (view === 'runtime' ? n.scope !== 'dev' : !!n.direct)
    const nodes: FNode[] = graph.nodes.filter(keep).map((n) => ({ ...n, installScript: byId.get(n.id)?.install_script }))
    const ids = new Set(nodes.map((n) => n.id))
    const links: FLink[] = graph.edges
      .filter((e: GraphEdge) => ids.has(e.source) && ids.has(e.target) && (view === 'all' || e.kind !== 'dev'))
      .map((e) => ({ ...e }))
    return { nodes, links }
  }, [graph, view, byId])

  const path = selected ? graph.paths[selected] ?? [selected] : []
  const onPath = new Set(path)
  const pathEdges = new Set(path.slice(1).map((t, i) => `${path[i]}>${t}`))

  const parents = selected ? graph.edges.filter((e) => e.target === selected) : []
  const children = selected ? graph.edges.filter((e) => e.source === selected) : []
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id

  function select(id: string | null) {
    setSelected(id)
    if (!id) return
    // frame the whole introduction path, not just the node
    const along = new Set(graph.paths[id] ?? [id])
    fg.current?.zoomToFit(600, 80, (n: FNode) => along.has(n.id))
  }

  function onSearch(v: string) {
    setQuery(v)
    const id = labelToId.get(v)
    if (id) {
      if (view !== 'all' && !data.nodes.some((n) => n.id === id)) setView('all')
      select(id)
    }
  }

  const c = selected ? byId.get(selected) : undefined
  return (
    <div className="graph-layout">
      <div className="graph-main card">
        <div className="graph-toolbar">
          <input list="pkg-list" placeholder="Find a package, e.g. crypto-js@3.3.0" value={query}
                 onChange={(e) => onSearch(e.target.value)} aria-label="Find package" />
          <datalist id="pkg-list">
            {graph.nodes.filter((n) => n.type === 'component').map((n) => <option key={n.id} value={n.label} />)}
          </datalist>
          <div className="seg">
            {(['all', 'runtime', 'direct'] as View[]).map((v) => (
              <button key={v} className={view === v ? 'active' : ''} onClick={() => setView(v)}>
                {v === 'all' ? 'All' : v === 'runtime' ? 'Hide dev' : 'Direct only'}
              </button>
            ))}
          </div>
          <span className="muted small">{data.nodes.length} nodes · {data.links.length} edges</span>
        </div>
        <div className="legend">
          {(['repo', 'project', 'direct', 'transitive', 'dev'] as const).map((k) => (
            <span key={k}><i style={{ background: COLORS[k] }} />{k === 'dev' ? 'dev-only' : k}</span>
          ))}
          <span><i className="ring" style={{ borderColor: COLORS.script }} />install script</span>
          <span><i style={{ background: COLORS.path }} />selected path</span>
        </div>
        <div className="graph-canvas" ref={wrap}>
          <ForceGraph2D
            ref={fg}
            width={size.w}
            height={size.h}
            graphData={data}
            backgroundColor="rgba(0,0,0,0)"
            nodeId="id"
            nodeLabel={(n: FNode) => n.label}
            nodeVal={(n: FNode) => (n.type === 'repo' ? 14 : n.type === 'project' ? 8 : onPath.has(n.id) ? 5 : 1 + Math.min(4, (n.dependents ?? 0) / 8))}
            nodeColor={(n: FNode) => (onPath.has(n.id) ? COLORS.path : nodeColor(n))}
            nodeCanvasObjectMode={() => 'after'}
            nodeCanvasObject={(n: FNode, ctx, scale) => {
              if (n.installScript) {
                ctx.beginPath()
                ctx.arc(n.x!, n.y!, 5, 0, 2 * Math.PI)
                ctx.strokeStyle = COLORS.script
                ctx.lineWidth = 1.2
                ctx.stroke()
              }
              if (n.type !== 'component' || onPath.has(n.id)) {
                ctx.font = `${Math.max(10 / scale, 2)}px Inter, sans-serif`
                ctx.fillStyle = '#e2e8f0'
                ctx.textAlign = 'center'
                ctx.fillText(n.label, n.x!, n.y! - 8)
              }
            }}
            linkColor={(l: FLink) => (pathEdges.has(`${idOf(l.source)}>${idOf(l.target)}`) ? COLORS.path : 'rgba(148,163,184,0.18)')}
            linkWidth={(l: FLink) => (pathEdges.has(`${idOf(l.source)}>${idOf(l.target)}`) ? 3 : 0.5)}
            linkDirectionalArrowLength={(l: FLink) => (pathEdges.has(`${idOf(l.source)}>${idOf(l.target)}`) ? 6 : 0)}
            linkDirectionalArrowRelPos={1}
            onNodeClick={(n: FNode) => select(n.id)}
            onBackgroundClick={() => setSelected(null)}
            onEngineStop={() => { if (!fitted.current) { fitted.current = true; fg.current?.zoomToFit(400, 30) } }}
            cooldownTicks={200}
            d3VelocityDecay={0.3}
          />
        </div>
      </div>

      <aside className="graph-side card">
        {!selected && (
          <div className="muted">
            <h2>Component details</h2>
            <p>Click a node or search for a package to see its metadata and how it entered the project.</p>
            <p className="small">Shortest introduction path is computed by the Dependency Graph agent from lockfile edges.</p>
          </div>
        )}
        {selected && (
          <>
            <div className="eyebrow">{c ? (c.direct ? 'Direct dependency' : 'Transitive dependency') : label(selected)}</div>
            <h2 className="mono">{label(selected)}</h2>
            <h3>Introduced via</h3>
            <ol className="path">
              {path.map((p) => (
                <li key={p}><button className="link" onClick={() => select(p)}>{label(p)}</button></li>
              ))}
            </ol>
            {c && (
              <dl className="facts">
                <dt>purl</dt><dd className="mono">{c.purl}</dd>
                <dt>Scope</dt><dd>{c.scope}</dd>
                <dt>License</dt><dd>{c.license ?? 'unknown'}</dd>
                <dt>Origin</dt><dd>{c.origin}</dd>
                {c.resolved && <><dt>Resolved</dt><dd className="mono small break">{c.resolved}</dd></>}
                {c.integrity && <><dt>Integrity</dt><dd className="mono small break">{c.integrity.slice(0, 40)}…</dd></>}
                <dt>Install script</dt><dd>{c.install_script ? <span className="chip generated">yes</span> : 'no'}</dd>
                <dt>Install paths</dt><dd>{c.install_paths}</dd>
                <dt>Projects</dt><dd>{c.projects.map((p) => p.replace('project:', '')).join(', ')}</dd>
              </dl>
            )}
            <h3>Required by ({parents.length})</h3>
            <ul className="deps">
              {parents.slice(0, 30).map((e) => (
                <li key={e.source + e.kind}><button className="link" onClick={() => select(e.source)}>{label(e.source)}</button> <span className="muted small">{e.kind}</span></li>
              ))}
            </ul>
            <h3>Depends on ({children.length})</h3>
            <ul className="deps">
              {children.slice(0, 30).map((e) => (
                <li key={e.target + e.kind}><button className="link" onClick={() => select(e.target)}>{label(e.target)}</button> <span className="muted small">{e.kind}</span></li>
              ))}
            </ul>
          </>
        )}
      </aside>
    </div>
  )
}
