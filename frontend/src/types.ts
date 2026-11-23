export type AgentStatus = 'pending' | 'running' | 'done' | 'partial' | 'failed' | 'skipped' | 'planned'

export interface Agent {
  name: string
  status: AgentStatus
  summary?: string
  duration?: number
  error?: string
}

export interface Component {
  id: string
  name: string
  version: string
  ecosystem: string
  purl: string
  direct: boolean
  scope: 'runtime' | 'dev' | 'optional'
  license: string | null
  origin: string
  resolved: string | null
  integrity: string | null
  install_script: boolean
  projects: string[]
  install_paths: number
}

export interface Project {
  id: string
  path: string
  ecosystem: string
  manifest: string
  name?: string
  version?: string
  lockfile?: string | null
  lock_source?: 'committed' | 'generated' | 'none'
  status: 'parsed' | 'partial' | 'failed'
  component_count: number
  declared_direct?: number
  notes: string[]
  evidence: { command?: string; npm_version?: string; generated_at?: string; sha256?: string; artifact?: string }
}

export interface GraphNode {
  id: string
  label: string
  type: 'repo' | 'project' | 'component'
  depth: number | null
  direct?: boolean
  scope?: string
  ecosystem?: string
  dependents?: number
  dependencies?: number
}

export interface GraphEdge { source: string; target: string; kind: string }

export interface Observation { file: string; line: number | null; text: string; level: 'info' | 'notice' | 'warning'; message: string }

export interface Results {
  checkout?: {
    owner: string; repo: string; url: string; commit_sha: string; branch: string
    commit_date: string; commit_author: string; commit_subject: string; tracked_files: number; clone: string
  }
  discovery?: {
    projects: Project[]
    unsupported: { path: string; ecosystem: string }[]
    warnings: string[]
    ecosystems: string[]
    components: Component[]
    stats: { components: number; direct: number; transitive: number; edges: number; install_scripts: number }
  }
  sbom?: {
    format: string; spec_version: string; artifact: string; sha256: string; size_bytes: number
    components: number; dependency_entries: number; serial_number: string
    crosschecks: { project: string; tool: string; ours: number; status: string; tool_count?: number; artifact?: string; error?: string }[]
  }
  graph?: {
    nodes: GraphNode[]; edges: GraphEdge[]; paths: Record<string, string[]>
    stats: { nodes: number; edges: number; max_depth: number; depth_histogram: Record<string, number>; unreachable: number }
    most_depended_on: { id: string; dependents: number }[]
  }
  inspection?: {
    dockerfiles: { file: string; images: { image: string; stage: string | null; line: number; pinning: string; level: string }[]; observations: Observation[] }[]
    workflows: { file: string; actions: { uses: string; line: number; kind: string; pinned: boolean; first_party: boolean }[]; observations: Observation[] }[]
    observations: Observation[]
    not_inspected: string[]
    stats: { dockerfiles: number; workflows: number; base_images: number; actions: number; unpinned_actions: number; warnings: number }
  }
}

export interface Scan {
  id: string
  repo_url: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  created_at: number
  commit_sha: string | null
  error: string | null
  agents: Record<string, Agent>
  results: Results
}

export type ScanSummary = Pick<Scan, 'id' | 'repo_url' | 'status' | 'commit_sha' | 'created_at'>

export const artifactUrl = (scanId: string, name: string) => `/api/scans/${scanId}/artifacts/${name}`
