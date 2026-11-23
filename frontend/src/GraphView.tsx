import { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import type { Component, GraphEdge, GraphNode, Results } from './types'

type G = NonNullable<Results['graph']>
type View = 'all' | 'runtime' | 'direct'
type FNode = GraphNode & { x?: number; y?: number; installScript?: boolean }
type FLink = { source: string | FNode; target: string | FNode; kind: string }

export type Theme = 'light' | 'dark'
// Edge alpha is tuned so links stay visible on each background without drowning the nodes.
const PALETTES = {
  dark: {
    repo: '#f8fafc', project: '#a78bfa', direct: '#2dd4bf', transitive: '#60a5fa', dev: '#64748b',
    path: '#facc15', script: '#fb923c', edge: 'rgba(148,163,184,0.42)', label: '#e2e8f0', halo: '#0b1120', hover: '#f472b6',
  },
  light: {
    repo: '#0f172a', project: '#7c3aed', direct: '#0d9488', transitive: '#2563eb', dev: '#94a3b8',
    path: '#d97706', script: '#c2410c', edge: 'rgba(51,65,85,0.38)', label: '#0f172a', halo: '#ffffff', hover: '#db2777',
  },
}
type Palette = (typeof PALETTES)['dark']
const REL_SIZE = 4
const LABEL_ZOOM = 2.5 // above this zoom every package gets a label
const esc = (s: string) => s.replace(/[&<>"]/g, (ch) => `&#${ch.charCodeAt(0)};`)
const idOf = (x: string | FNode) => (typeof x === 'string' ? x : x.id)

function nodeColor(n: FNode, COLORS: Palette) {
  if (n.type === 'repo') return COLORS.repo
  if (n.type === 'project') return COLORS.project
  if (n.scope === 'dev') return COLORS.dev
  return n.direct ? COLORS.direct : COLORS.transitive
}

export default function GraphView({ graph, components, theme }: { graph: G; components: Component[]; theme: Theme }) {
  const COLORS = PALETTES[theme]
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

  const [hover, setHover] = useState<string | null>(null)
  const neighbors = useMemo(() => {
    const m = new Map<string, Set<string>>()
    for (const e of graph.edges) {
      if (!m.has(e.source)) m.set(e.source, new Set())
      if (!m.has(e.target)) m.set(e.target, new Set())
      m.get(e.source)!.add(e.target)
      m.get(e.target)!.add(e.source)
    }
    return m
  }, [graph])
  const hoverSet = new Set(hover ? [hover, ...(neighbors.get(hover) ?? [])] : [])
  const touchesHover = (l: FLink) => !!hover && (idOf(l.source) === hover || idOf(l.target) === hover)

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

  const nodeVal = (n: FNode) =>
    n.type === 'repo' ? 14 : n.type === 'project' ? 8 : onPath.has(n.id) ? 5 : 1 + Math.min(4, (n.dependents ?? 0) / 8)
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
          <span><i style={{ background: COLORS.hover }} />hovered + neighbours</span>
          <span className="hint">Hover a dot for its name, zoom in (scroll) to label every package, click for details</span>
        </div>
        <div className="graph-canvas" ref={wrap}>
          <ForceGraph2D
            ref={fg}
            width={size.w}
            height={size.h}
            graphData={data}
            backgroundColor="rgba(0,0,0,0)"
            nodeId="id"
            nodeLabel={(n: FNode) => {
              const kind = n.type !== 'component' ? n.type : n.direct ? 'direct dependency' : 'transitive dependency'
              const extra = n.type === 'component'
                ? `<br>${n.scope} · depth ${n.depth ?? '?'} · ${n.dependents ?? 0} dependents${n.installScript ? ' · install script' : ''}` : ''
              return `<b>${esc(n.label)}</b><br><span>${kind}</span>${extra}<br><i>click for details</i>`
            }}
            onNodeHover={(n: FNode | null) => setHover(n?.id ?? null)}
            nodeVal={nodeVal}
            nodeRelSize={REL_SIZE}
            // Hit area never smaller than ~8 screen px, so tiny nodes stay clickable when zoomed out.
            nodePointerAreaPaint={(n: FNode, color, ctx, scale) => {
              ctx.fillStyle = color
              ctx.beginPath()
              ctx.arc(n.x!, n.y!, Math.max(Math.sqrt(nodeVal(n)) * REL_SIZE, 8 / scale), 0, 2 * Math.PI)
              ctx.fill()
            }}
            nodeColor={(n: FNode) => (onPath.has(n.id) ? COLORS.path : nodeColor(n, COLORS))}
            nodeCanvasObjectMode={() => 'after'}
            nodeCanvasObject={(n: FNode, ctx, scale) => {
              if (n.installScript) {
                ctx.beginPath()
                ctx.arc(n.x!, n.y!, 5, 0, 2 * Math.PI)
                ctx.strokeStyle = COLORS.script
                ctx.lineWidth = 1.2
                ctx.stroke()
              }
              // Labels: repo/projects, selected path and hovered neighbourhood always; direct deps once not fully zoomed out
              // (154 overlapping labels on Juice Shop otherwise); every package past LABEL_ZOOM.
              if (n.type !== 'component' || (n.direct && scale >= 1) || onPath.has(n.id) || hoverSet.has(n.id) || scale >= LABEL_ZOOM) {
                const size = 11 / scale
                ctx.font = `${n.id === hover || onPath.has(n.id) ? 600 : 400} ${size}px Inter, sans-serif`
                ctx.textAlign = 'center'
                ctx.textBaseline = 'bottom'
                const y = n.y! - Math.sqrt(nodeVal(n)) * REL_SIZE - 2 / scale
                ctx.lineWidth = 3 / scale
                ctx.strokeStyle = COLORS.halo
                ctx.strokeText(n.label, n.x!, y)
                ctx.fillStyle = n.id === hover ? COLORS.hover : COLORS.label
                ctx.fillText(n.label, n.x!, y)
              }
            }}
            linkColor={(l: FLink) => (pathEdges.has(`${idOf(l.source)}>${idOf(l.target)}`) ? COLORS.path : touchesHover(l) ? COLORS.hover : COLORS.edge)}
            linkWidth={(l: FLink) => (pathEdges.has(`${idOf(l.source)}>${idOf(l.target)}`) ? 3 : touchesHover(l) ? 2 : 0.8)}
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

      <aside className={`graph-side card ${selected ? 'open' : ''}`}>
        {!selected && (
          <div className="muted">
            <h2>Component details</h2>
            <p>Click a node or search for a package to see its metadata and how it entered the project.</p>
            <p className="small">Shortest introduction path is computed by the Dependency Graph agent from lockfile edges.</p>
          </div>
        )}
        {selected && (
          <>
            <div className="side-head">
              <div className="eyebrow">{c ? (c.direct ? 'Direct dependency' : 'Transitive dependency') : label(selected)}</div>
              <button className="close" onClick={() => setSelected(null)} aria-label="Close details">×</button>
            </div>
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
                <dt>Projects</dt><dd>{c.projects.map(label).join(', ')}</dd>
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
