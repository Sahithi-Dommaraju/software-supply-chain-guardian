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

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unrated' | 'none'

export interface VulnFinding {
  id: string; type: 'vulnerability'; advisory_id: string; aliases: string[]; cves: string[]
  title: string; severity: Severity; severity_source: string; cvss_score: number | null; cvss_vector: string | null
  advisory_label: string | null; cwe: string[]; fixed_versions: string[]; fix: string | null
  published?: string; url: string; component: string; name: string; version: string; ecosystem: string
  direct: boolean | null; scope: string | null; path: string[] | null; project: string; also_in?: string[]
  trivy_confirmed?: boolean
}

export interface SuspiciousFinding {
  id: string; type: 'suspicious'; rule: string; category: string; title: string
  severity: 'high' | 'medium' | 'low'; status: 'fact' | 'indicator'; rationale: string
  evidence: { file?: string; line?: number | null; text?: string; source?: string; field?: string; resolved?: string | null; lookalike_of?: string; notes?: string[]; command?: string }
  component: string | null; name: string | null; version: string | null; direct: boolean | null
  scope: string | null; path: string[] | null; project: string | null
}

export interface Bundle {
  finding_id: string; type: 'vulnerability' | 'suspicious'; title: string; severity: string
  advisory_id?: string | null; aliases: string[]; rule?: string | null; category: string
  component: { purl: string; name: string; version: string; direct: boolean; scope: string } | null
  project: string | null; dependency_path: string[]; fix: string | null
  evidence_refs: { kind: string; ref: string; line?: number | null; detail?: string }[]
  verified_facts: string[]; inference: string[]; unknowns: string[]
  initial_risk: { level: 'critical' | 'high' | 'medium' | 'low' | 'review'; rationale: string }
}

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
  vulnerability?: {
    scans: { project: string; manifest: string; status: string; command?: string; tool_version?: string; mode?: string
             scanned_at?: string; target?: string; target_sha256?: string; artifact?: string; findings?: number
             packages_affected?: number; error?: string; reason?: string
             trivy?: { version: string; status: string; artifact?: string; trivy_entries?: number; matched_osv?: number; only_trivy?: string[]; error?: string } }[]
    findings: VulnFinding[]
    counts: Record<'critical' | 'high' | 'medium' | 'low' | 'unrated', number>
    packages_affected: number
  }
  change_detection?: {
    findings: SuspiciousFinding[]
    by_rule: Record<string, number>
    not_applicable: { rule: string; reason: string }[]
    counts: Record<'high' | 'medium' | 'low', number>
  }
  evidence?: {
    report: {
      repository: string; repo_url: string; commit_sha: string; generated_at: string
      inventory: { components: number; direct: number; transitive: number; edges: number }
      risk_counts: Record<string, number>; by_type: Record<string, number>
      coverage: { agents: { name: string; status: string; summary?: string }[]; gaps: string[] }
      checklist: { item: string; done: boolean }[]
    }
    bundles: Bundle[]
    artifacts: { json: string; markdown: string }
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
