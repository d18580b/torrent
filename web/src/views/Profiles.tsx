import { useQuery } from '@tanstack/react-query'
import { api, type ProfileSummary, type Status } from '../lib/api'
import { count, rate } from '../lib/format'
import { Card, ErrorBanner } from '../components/Bits'

/// Pill colour for a profile status.
///
/// `active`, `vpn_down` and `failed` are the three values `/api/profiles`
/// returns, and the two non-active ones are not the same thing: a fenced
/// profile has a session and lost its tunnel, and is the case the banner below
/// tells the operator how to clear; a failed profile never got a session at
/// all, so nothing about it will change without a restart. They were both
/// rendered through one pill, which made them indistinguishable at exactly the
/// moment an operator is scanning the column to find out which they have.
///
/// The severity class and the label are separate here because they say
/// different things: the class is `styles.css`'s existing palette, the label is
/// the status itself rather than a word from the pool's adoption vocabulary.
function statusSeverity(status: string): string {
  if (status === 'active') return 'adopted'
  if (status === 'vpn_down') return 'drifted'
  return 'missing'
}

/// Session health. Each profile is a libtorrent session with its own network
/// posture — a VPN tunnel, or the host's own interfaces — and a fenced profile
/// is the thing an operator most needs to notice: it stops seeding and will not
/// resume without intervention.
export function Profiles() {
  const status = useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/api/status') })
  const profiles = useQuery({
    queryKey: ['profiles'],
    queryFn: () => api.get<ProfileSummary[]>('/api/profiles'),
    retry: false,
  })

  const s = status.data

  return (
    <div className="stack">
      <h2>Profiles</h2>
      <ErrorBanner error={status.error} />

      {s && (
        <div className="cards">
          <Card label="Torrents" value={count(s.torrents_total)} />
          <Card label="Seeding" value={count(s.seeding)} />
          <Card label="Upload" value={rate(s.upload_rate_total)} />
          <Card label="Paused" value={count(s.paused)} />
          <Card label="Errored" value={count(s.errored)} />
          <Card label="Pending resume" value={count(s.pending_resume_count)} />
        </div>
      )}

      {/* `/api/profiles` is mounted unconditionally — a daemon always has at
          least one profile, and one with no `[[profile]]` table cannot boot —
          so an error here is auth or the network, never a configuration to
          fix. The banner this replaces told an operator whose session had
          lapsed that their config was wrong. */}
      <ErrorBanner error={profiles.error} />

      {profiles.data && profiles.data.length > 0 && (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Profile</th><th>Status</th><th>Tunnel IP</th>
                <th className="num">Port</th><th>Forwarding</th>
                <th className="num">Torrents</th><th>User agent</th>
              </tr>
            </thead>
            <tbody>
              {profiles.data.map((sl) => (
                <tr key={sl.profile_id}>
                  <td><strong>{sl.profile_id}</strong></td>
                  <td>
                    <span className={`pill ${statusSeverity(sl.status)}`}>{sl.status}</span>
                  </td>
                  <td className="mono">{sl.tunnel_ip ?? '—'}</td>
                  <td className="num mono">{sl.forwarded_port ?? sl.listen_port ?? '—'}</td>
                  <td className="small muted">{sl.port_forward}</td>
                  <td className="num">{count(sl.torrent_count)}</td>
                  <td className="small muted">{sl.user_agent}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {profiles.data?.some((sl) => sl.status === 'vpn_down') && (
        <div className="banner err">
          A profile is fenced: its tunnel failed, every torrent in it was paused, and it will not
          resume automatically. Fix the tunnel and restart the daemon.
        </div>
      )}
    </div>
  )
}
