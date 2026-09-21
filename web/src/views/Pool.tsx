import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  adoptPool,
  api,
  type AdoptResponse,
  type PoolOverview,
  type ProfileSummary,
  type TreeResponse,
} from '../lib/api'
import { bytes, count } from '../lib/format'
import { Card, ErrorBanner, ProtectionBar, StatePill } from '../components/Bits'

/// The filesystem, annotated with what is protected and what is not.
///
/// This is the primary view because at pool scale the useful question is not
/// "which torrents do I have" but "which of these bytes is nothing looking
/// after". Directories carry rollups so that question is answerable without
/// expanding anything.
export function Pool() {
  const qc = useQueryClient()
  const [rootId, setRootId] = useState<number | null>(null)
  const [path, setPath] = useState('')
  const [notice, setNotice] = useState<string | null>(null)
  const [profileId, setProfileId] = useState<string | null>(null)

  const overview = useQuery({
    queryKey: ['pool', 'overview'],
    queryFn: () => api.get<PoolOverview>('/api/pool'),
  })

  // Adoption hands every matched torrent to one profile's session, and the
  // daemon requires the caller to say which — there is no default, and a
  // profile is an account identity, so guessing one is not a safe fallback.
  const profiles = useQuery({
    queryKey: ['profiles'],
    queryFn: () => api.get<ProfileSummary[]>('/api/profiles'),
  })

  // `/api/profiles` lists live profiles in configured order and then the ones
  // that failed to come up, so `data[0]` is an `active` profile only when at
  // least one came up. A failed profile carries no session, and adopting into
  // one answers 409 — so default to, and offer, only the active ones.
  const adoptable = (profiles.data ?? []).filter((p) => p.status === 'active')

  const activeRoot = rootId ?? overview.data?.roots[0]?.root_id ?? null
  const activeProfile = profileId ?? adoptable[0]?.profile_id ?? null

  const tree = useQuery({
    queryKey: ['pool', 'tree', activeRoot, path],
    queryFn: () =>
      api.get<TreeResponse>(`/api/pool/tree?root_id=${activeRoot}&path=${encodeURIComponent(path)}`),
    enabled: activeRoot !== null,
  })

  const scan = useMutation({
    mutationFn: () => api.post('/api/pool/scan'),
    onSuccess: () => {
      setNotice('Scan complete.')
      qc.invalidateQueries({ queryKey: ['pool'] })
    },
  })

  const [preview, setPreview] = useState<AdoptResponse | null>(null)

  // `activeProfile` is null only before `/api/profiles` resolves; both buttons
  // are disabled until then rather than sending a request the daemon refuses.
  const dryRun = useMutation({
    mutationFn: () => {
      if (activeProfile === null) throw new Error('no profile to adopt into')
      return adoptPool({ profile_id: activeProfile, root_id: activeRoot, path, dry_run: true })
    },
    onSuccess: setPreview,
  })

  const adopt = useMutation({
    mutationFn: () => {
      if (activeProfile === null) throw new Error('no profile to adopt into')
      return adoptPool({ profile_id: activeProfile, root_id: activeRoot, path })
    },
    onSuccess: (r) => {
      setPreview(null)
      setNotice(
        `Adopted ${r.fast_path.length} immediately; ${r.queued_for_verification.length} queued for verification` +
          (r.refused.length ? `; ${r.refused.length} refused` : '') + '.',
      )
      qc.invalidateQueries({ queryKey: ['pool'] })
      qc.invalidateQueries({ queryKey: ['torrents'] })
    },
  })

  if (overview.isError) return <ErrorBanner error={overview.error} />
  if (!overview.data) return <p className="muted">Loading…</p>

  const o = overview.data
  if (o.roots.length === 0) {
    return (
      <div className="stack">
        <h2>Pool</h2>
        <div className="banner">
          No managed roots are configured. Add a <code>[pool]</code> section with{' '}
          <code>roots</code> and <code>library_dir</code> to the daemon's config.
        </div>
      </div>
    )
  }

  const segments = path ? path.split('/') : []

  return (
    <div className="stack">
      <div className="between">
        <h2 style={{ margin: 0 }}>Pool</h2>
        <div className="row">
          <button className="ghost" onClick={() => scan.mutate()} disabled={scan.isPending}>
            {scan.isPending ? 'Scanning…' : 'Rescan'}
          </button>
          <label className="row small">
            Adopt into
            <select
              value={activeProfile ?? ''}
              onChange={(e) => setProfileId(e.target.value)}
              disabled={adoptable.length === 0}
            >
              {adoptable.map((p) => (
                <option key={p.profile_id} value={p.profile_id}>{p.profile_id}</option>
              ))}
            </select>
          </label>
          <button
            className="ghost"
            onClick={() => dryRun.mutate()}
            disabled={dryRun.isPending || activeProfile === null}
          >
            Adopt this subtree…
          </button>
        </div>
      </div>

      {notice && <div className="banner">{notice}</div>}
      <ErrorBanner error={profiles.error ?? scan.error ?? dryRun.error ?? adopt.error} />

      <div className="cards">
        <Card label="Torrents" value={count(o.torrents)} />
        <Card label="Files indexed" value={count(o.files)} />
        <Card label="Adopted" value={count(o.states.adopted ?? 0)} />
        <Card
          label="Needs attention"
          value={count((o.states.partial ?? 0) + (o.states.missing ?? 0) + (o.states.overlap ?? 0) + (o.states.drifted ?? 0))}
          sub="partial · missing · overlap · drifted"
        />
        <Card
          label="Verifying"
          value={count(o.verify_in_flight)}
          sub={o.verify_queue_depth ? `${count(o.verify_queue_depth)} queued` : undefined}
        />
      </div>

      {o.roots.length > 1 && (
        <div className="row">
          {o.roots.map((r) => (
            <button
              key={r.root_id}
              className="ghost"
              aria-current={r.root_id === activeRoot ? 'page' : undefined}
              onClick={() => { setRootId(r.root_id); setPath('') }}
            >
              {r.path}
            </button>
          ))}
        </div>
      )}

      <div className="crumbs">
        <button onClick={() => setPath('')}>
          {o.roots.find((r) => r.root_id === activeRoot)?.path ?? '/'}
        </button>
        {segments.map((seg, i) => (
          <span key={i} className="row">
            <span className="sep">/</span>
            <button onClick={() => setPath(segments.slice(0, i + 1).join('/'))}>{seg}</button>
          </span>
        ))}
      </div>

      {tree.data && (
        <>
          <div className="cards">
            <Card label="Here" value={bytes(tree.data.bytes_total)} sub={`${count(tree.data.files_total)} files`} />
            <Card label="Adopted" value={bytes(tree.data.bytes_adopted)} />
            <Card label="Matched" value={bytes(tree.data.bytes_matched)} />
            <Card
              label="Unclaimed"
              value={bytes(tree.data.bytes_orphan)}
              sub={tree.data.files_orphan ? `${count(tree.data.files_orphan)} files` : undefined}
            />
          </div>

          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th className="num">Size</th>
                  <th style={{ width: 160 }}>Protected</th>
                  <th className="num">Unclaimed</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {tree.data.entries.map((e) => (
                  <tr key={e.path}>
                    <td>
                      {e.is_dir ? (
                        <button
                          className="mono"
                          style={{ background: 'none', border: 0, color: 'var(--accent)', cursor: 'pointer', padding: 0 }}
                          onClick={() => setPath(e.path)}
                        >
                          {e.name}/
                        </button>
                      ) : (
                        <span className="mono">{e.name}</span>
                      )}
                    </td>
                    <td className="num">{bytes(e.bytes_total)}</td>
                    <td><ProtectionBar r={e} /></td>
                    <td className="num">{e.bytes_orphan ? bytes(e.bytes_orphan) : '—'}</td>
                    <td>
                      <div className="row">
                        {e.states.map((s) => <StatePill key={s} state={s} />)}
                      </div>
                    </td>
                  </tr>
                ))}
                {tree.data.entries.length === 0 && (
                  <tr><td colSpan={5} className="muted">Nothing indexed here.</td></tr>
                )}
              </tbody>
            </table>
          </div>
          {tree.data.truncated && (
            <p className="muted small">
              Listing truncated. Narrow the path to see the rest.
            </p>
          )}
        </>
      )}

      {preview && (
        <AdoptDialog
          preview={preview}
          path={path}
          profileId={activeProfile ?? ''}
          busy={adopt.isPending}
          onCancel={() => setPreview(null)}
          onConfirm={() => adopt.mutate()}
        />
      )}
    </div>
  )
}

/// The dry run, shown before anything is handed to a session. `verify_bytes` is
/// the number that decides whether this is minutes or days of disk reads, so it
/// is the one called out.
function AdoptDialog({
  preview,
  path,
  profileId,
  busy,
  onCancel,
  onConfirm,
}: {
  preview: AdoptResponse
  path: string
  profileId: string
  busy: boolean
  onCancel: () => void
  onConfirm: () => void
}) {
  const nothing =
    preview.fast_path.length === 0 && preview.queued_for_verification.length === 0
  return (
    <dialog open>
      <h3 style={{ marginTop: 0 }}>
        Adopt {path ? <code>{path}</code> : 'the whole root'} into <code>{profileId}</code>
      </h3>
      <ul style={{ paddingLeft: 18, lineHeight: 1.8 }}>
        <li>
          <strong>{preview.fast_path.length}</strong> seed immediately — resume data says
          complete and the files still match.
        </li>
        <li>
          <strong>{preview.queued_for_verification.length}</strong> verified first —{' '}
          <strong>{bytes(preview.verify_bytes)}</strong> for libtorrent to hash.
        </li>
        {preview.refused.length > 0 && (
          <li><strong>{preview.refused.length}</strong> refused.</li>
        )}
      </ul>
      {preview.refused.length > 0 && (
        <div className="scroll" style={{ maxHeight: 180 }}>
          <table>
            <thead><tr><th>Torrent</th><th>Reason</th></tr></thead>
            <tbody>
              {preview.refused.slice(0, 25).map((r) => (
                <tr key={r.infohash}>
                  <td className="mono">{r.infohash.slice(0, 12)}</td>
                  <td className="small">{r.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="row" style={{ marginTop: 16, justifyContent: 'flex-end' }}>
        <button className="ghost" onClick={onCancel}>Cancel</button>
        <button className="action" onClick={onConfirm} disabled={busy || nothing}>
          {busy ? 'Adopting…' : 'Adopt'}
        </button>
      </div>
    </dialog>
  )
}
