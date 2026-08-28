import type { Rollup } from '../lib/api'
import { bytes, protectedPct } from '../lib/format'

export function StatePill({ state }: { state: string }) {
  return <span className={`pill ${state}`}>{state}</span>
}

/// Adopted (solid) and matched (faded) against the total, so an unprotected
/// subtree is obvious without reading three numbers.
export function ProtectionBar({ r }: { r: Rollup }) {
  const pct = protectedPct(r)
  if (pct === null) return <span className="muted small">empty</span>
  const adopted = (r.bytes_adopted / r.bytes_total) * 100
  const matched = (r.bytes_matched / r.bytes_total) * 100
  return (
    <div title={`${bytes(r.bytes_adopted)} adopted, ${bytes(r.bytes_matched)} matched, ${bytes(r.bytes_orphan)} unclaimed`}>
      <div className="bar">
        <div className="adopted" style={{ width: `${adopted}%` }} />
        <div className="matched" style={{ width: `${matched}%` }} />
      </div>
      <div className="muted small" style={{ marginTop: 2 }}>{pct.toFixed(0)}% protected</div>
    </div>
  )
}

export function Card({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="card">
      <div className="label">{label}</div>
      <div className="value">
        {value} {sub && <small>{sub}</small>}
      </div>
    </div>
  )
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null
  return <div className="banner err">{error instanceof Error ? error.message : String(error)}</div>
}
