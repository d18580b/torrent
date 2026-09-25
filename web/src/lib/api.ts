// Typed access to the daemon's HTTP surface.
//
// Every call is same-origin so the SameSite=Strict session cookie rides along
// on its own; nothing here touches a token, and none is ever stored in the
// browser. A 401 anywhere means the session lapsed, which the app turns into a
// return to the login screen rather than a wall of failed panels.

export class Unauthorized extends Error {
  constructor() {
    super('authentication required')
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
  })
  if (res.status === 401) throw new Unauthorized()
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      if (body?.error) detail = body.error
    } catch {
      // Non-JSON error body; the status text is the best we have.
    }
    throw new Error(detail)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const api = {
  get: <T,>(p: string) => request<T>(p),
  post: <T,>(p: string, body?: unknown) =>
    request<T>(p, { method: 'POST', body: body ? JSON.stringify(body) : undefined }),
  del: <T,>(p: string) => request<T>(p, { method: 'DELETE' }),
}

// -- shapes mirroring the daemon's serde output -----------------------------

export interface Rollup {
  bytes_total: number
  bytes_adopted: number
  bytes_matched: number
  bytes_orphan: number
  files_total: number
  files_orphan: number
}

export interface RootSummary extends Rollup {
  root_id: number
  path: string
}

export interface PoolOverview {
  roots: RootSummary[]
  library_dir: string
  torrents: number
  files: number
  states: Record<string, number>
  verify_queue_depth: number
  verify_in_flight: number
}

export interface TreeEntry extends Rollup {
  name: string
  path: string
  is_dir: boolean
  states: string[]
}

export interface TreeResponse extends Rollup {
  root_id: number
  path: string
  entries: TreeEntry[]
  truncated: boolean
}

export interface PoolTorrent {
  infohash: string
  name: string
  total_size: number
  num_files: number
  state: string | null
  base_rel: string | null
  profile: string | null
  category: string | null
  tags: string[]
  has_fastresume: boolean
}

export interface TorrentSummary {
  infohash: string
  profile_id: string
  phase: string
  upload_rate: number
  download_rate: number
  total_uploaded: number
  total_payload_uploaded: number
  num_peers: number
  progress: number
  is_finished: boolean
  is_seeding: boolean
}

export interface Status {
  torrents_total: number
  seeding: number
  paused: number
  disk_error: number
  errored: number
  upload_rate_total: number
  download_rate_total: number
  pending_resume_count: number
  profile_count: number
}

/// One row of `GET /api/profiles`.
///
/// Mirrors `crates/torrentd/src/http/profiles.rs`'s `ProfileSummary`, which is
/// the contract. The list is live profiles in configured order, then the ones
/// that failed to come up — but a client that needs an adoptable profile
/// filters on `status === 'active'` rather than taking the first row.
export interface ProfileSummary {
  profile_id: string
  /// `active` | `vpn_down` | `failed`.
  status: string
  tunnel_ip: string | null
  torrent_count: number
  listen_port: number | null
  port_forward: string
  forwarded_port: number | null
  /// `Option<String>` on the wire: null for a host profile that did not
  /// override it, which is every profile in the shipped sample.
  user_agent: string | null
  /// Why the profile has no session. Present only when `status` is `failed` —
  /// the field is skipped entirely otherwise.
  failure_reason?: string
}

/// The body `POST /api/pool/adopt` requires.
///
/// `profile_id` is not optional: the handler rejects a request without one
/// with 400, in every configuration. Declaring it required here is what makes
/// omitting it a build failure rather than a button that silently 400s —
/// which is what the adopt and preview buttons did, because the server made
/// the field mandatory and no call site here ever sent it.
export interface AdoptRequest {
  profile_id: string
  root_id?: number | null
  path?: string
  infohashes?: string[]
  dry_run?: boolean
}

export function adoptPool(body: AdoptRequest): Promise<AdoptResponse> {
  return api.post<AdoptResponse>('/api/pool/adopt', body)
}

export interface AdoptResponse {
  dry_run: boolean
  fast_path: string[]
  queued_for_verification: string[]
  refused: { infohash: string; reason: string }[]
  verify_bytes: number
}

export interface PlanStep {
  seq: number
  op: string
  src: string
  dst: string | null
  status: string
  error: string | null
}

export interface PlanView {
  id: number
  kind: string
  status: string
  created_at: number
  applied_at: number | null
  steps: PlanStep[]
  confirm_token: string | null
}
