import { useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { api, type PoolTorrent, type TorrentSummary } from '../lib/api'
import { bytes, count, rate } from '../lib/format'
import { ErrorBanner, StatePill } from '../components/Bits'

interface Row {
  infohash: string
  name: string
  size: number
  state: string | null
  phase: string
  up: number
  uploaded: number
  peers: number
  profile: string | null
}

/// The torrent list, virtualised.
///
/// A hundred thousand rows is the design point, so the table renders only what
/// is on screen. Names come from the pool index rather than the live status —
/// carrying a name per torrent through `state_update_alert` would cost a
/// fixed-size path buffer per torrent per tick.
export function Torrents() {
  const [filter, setFilter] = useState('')
  const [onlyProblems, setOnlyProblems] = useState(false)
  const parentRef = useRef<HTMLDivElement>(null)

  const live = useQuery({
    queryKey: ['torrents', 'live'],
    queryFn: () => api.get<{ items: TorrentSummary[] }>('/api/torrents?limit=1000'),
  })
  const pool = useQuery({
    queryKey: ['pool', 'torrents'],
    queryFn: () => api.get<PoolTorrent[]>('/api/pool/torrents?limit=5000'),
    // The pool is optional; a daemon without it still shows live state.
    retry: false,
  })

  const rows = useMemo<Row[]>(() => {
    const meta = new Map((pool.data ?? []).map((t) => [t.infohash, t]))
    const seen = new Set<string>()
    const out: Row[] = []

    for (const t of live.data?.items ?? []) {
      const m = meta.get(t.infohash)
      seen.add(t.infohash)
      out.push({
        infohash: t.infohash,
        name: m?.name ?? t.infohash.slice(0, 16),
        size: m?.total_size ?? 0,
        state: m?.state ?? null,
        phase: t.phase,
        up: t.upload_rate,
        uploaded: t.total_uploaded,
        peers: t.num_peers,
        profile: t.profile_id,
      })
    }
    // Torrents the pool knows about but that are not loaded: the ones that need
    // attention, and exactly what a live-only list would hide.
    for (const m of pool.data ?? []) {
      if (seen.has(m.infohash)) continue
      out.push({
        infohash: m.infohash,
        name: m.name,
        size: m.total_size,
        state: m.state,
        phase: '—',
        up: 0,
        uploaded: 0,
        peers: 0,
        profile: m.profile,
      })
    }
    return out
  }, [live.data, pool.data])

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    return rows.filter((r) => {
      if (onlyProblems && !['partial', 'missing', 'overlap', 'drifted'].includes(r.state ?? '')) {
        return false
      }
      if (!q) return true
      return r.name.toLowerCase().includes(q) || r.infohash.includes(q)
    })
  }, [rows, filter, onlyProblems])

  const virt = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 33,
    overscan: 12,
  })

  return (
    <div className="stack">
      <div className="between">
        <h2 style={{ margin: 0 }}>Torrents</h2>
        <div className="row">
          <input
            placeholder="Filter by name or infohash"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{
              padding: '6px 10px', border: '1px solid var(--border)',
              borderRadius: 6, background: 'var(--panel)', color: 'var(--text)', width: 250,
            }}
          />
          <label className="row small muted" style={{ gap: 5 }}>
            <input type="checkbox" checked={onlyProblems} onChange={(e) => setOnlyProblems(e.target.checked)} />
            Needs attention
          </label>
        </div>
      </div>

      <ErrorBanner error={live.error} />
      <p className="muted small" style={{ margin: 0 }}>
        {count(filtered.length)} of {count(rows.length)} shown
      </p>

      <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--panel)' }}>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th className="num">Size</th>
              <th>State</th>
              <th>Phase</th>
              <th className="num">Up</th>
              <th className="num">Uploaded</th>
              <th className="num">Peers</th>
              <th>Profile</th>
            </tr>
          </thead>
        </table>
        <div ref={parentRef} style={{ height: 'calc(100vh - 290px)', overflow: 'auto' }}>
          <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
            <table style={{ position: 'absolute', top: 0, left: 0, width: '100%' }}>
              <tbody>
                {virt.getVirtualItems().map((v) => {
                  const r = filtered[v.index]
                  return (
                    <tr
                      key={r.infohash}
                      style={{
                        position: 'absolute', top: 0, left: 0, width: '100%',
                        transform: `translateY(${v.start}px)`, display: 'table', tableLayout: 'fixed',
                      }}
                    >
                      <td title={r.infohash}>{r.name}</td>
                      <td className="num">{r.size ? bytes(r.size) : '—'}</td>
                      <td>{r.state ? <StatePill state={r.state} /> : <span className="muted">—</span>}</td>
                      <td>{r.phase === 'seeding' ? <StatePill state="seeding" /> : <span className="muted small">{r.phase}</span>}</td>
                      <td className="num">{rate(r.up)}</td>
                      <td className="num">{r.uploaded ? bytes(r.uploaded) : '—'}</td>
                      <td className="num">{r.peers || '—'}</td>
                      <td className="small muted">{r.profile ?? '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      {filtered.length === 0 && <p className="muted">Nothing matches.</p>}
    </div>
  )
}
