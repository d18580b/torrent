/// Binary units, matching what the daemon's CLI prints and what a filesystem
/// reports. Mixing SI and binary on the same screen is how people misjudge a
/// pool by ten percent.
const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'] as const

export function bytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—'
  if (n < 1024) return `${n} B`
  let v = n
  let i = 0
  while (v >= 1024 && i + 1 < UNITS.length) {
    v /= 1024
    i++
  }
  return `${v.toFixed(1)} ${UNITS[i]}`
}

export function rate(n: number): string {
  return n > 0 ? `${bytes(n)}/s` : '—'
}

export function count(n: number): string {
  return n.toLocaleString()
}

/// Percentage of a subtree that is protected by a torrent. Returns null for an
/// empty directory so the caller can render nothing rather than a misleading
/// 0% or 100%.
export function protectedPct(r: {
  bytes_total: number
  bytes_adopted: number
  bytes_matched: number
}): number | null {
  if (r.bytes_total === 0) return null
  return ((r.bytes_adopted + r.bytes_matched) / r.bytes_total) * 100
}
