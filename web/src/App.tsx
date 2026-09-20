import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, Unauthorized, type Status } from './lib/api'
import { Login } from './views/Login'
import { Pool } from './views/Pool'
import { Torrents } from './views/Torrents'
import { Slots } from './views/Slots'

type View = 'pool' | 'torrents' | 'slots'

const VIEWS: View[] = ['pool', 'torrents', 'slots']

/// Hash routing, not path routing.
///
/// The daemon still serves the pre-`/api` aliases for backwards compatibility,
/// so `/pool`, `/torrents` and `/slots` are all real API endpoints. A path-based
/// client route would collide with them and get a 401 instead of the app. A
/// fragment is never sent to the server, so `#/pool` cannot collide with
/// anything, and views stay bookmarkable and back-button friendly.
function viewFromHash(): View {
  const raw = window.location.hash.replace(/^#\/?/, '')
  return (VIEWS as string[]).includes(raw) ? (raw as View) : 'pool'
}

export function App() {
  const qc = useQueryClient()
  const [view, setViewState] = useState<View>(viewFromHash)

  // Keep the fragment and the rendered view in step in both directions, so the
  // back button works and a pasted link lands where it says.
  useEffect(() => {
    const onHash = () => setViewState(viewFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const setView = (v: View) => {
    window.location.hash = `/${v}`
    setViewState(v)
  }
  const [authed, setAuthed] = useState<boolean | null>(null)

  // One probe decides whether to show the app or the login screen. /status is
  // the cheapest authenticated endpoint; a 401 is the only signal that matters.
  const probe = useQuery({
    queryKey: ['status'],
    queryFn: () => api.get<Status>('/api/status'),
    retry: false,
  })

  useEffect(() => {
    if (probe.isSuccess) setAuthed(true)
    else if (probe.error instanceof Unauthorized) setAuthed(false)
    else if (probe.isError) setAuthed(true) // a non-auth error is the app's to show
  }, [probe.isSuccess, probe.isError, probe.error])

  // Live updates. The daemon emits a tick whenever torrent state changes;
  // invalidating is enough — refetching only what is mounted keeps this cheap
  // even with a very large pool.
  useEffect(() => {
    if (!authed) return
    const es = new EventSource('/api/events')
    es.addEventListener('tick', () => {
      qc.invalidateQueries({ queryKey: ['status'] })
      qc.invalidateQueries({ queryKey: ['torrents'] })
      qc.invalidateQueries({ queryKey: ['pool'] })
    })
    // On error EventSource reconnects by itself; the polling fallback covers
    // the gap, so there is nothing to do here but let it retry.
    return () => es.close()
  }, [authed, qc])

  if (authed === null) return <div style={{ padding: 40 }} className="muted">Loading…</div>
  if (!authed) return <Login onDone={() => { setAuthed(true); qc.invalidateQueries() }} />

  return (
    <div className="app">
      <nav className="side">
        <h1>torrentd</h1>
        <p className="sub">managed pool</p>
        <button aria-current={view === 'pool' ? 'page' : undefined} onClick={() => setView('pool')}>
          Pool
        </button>
        <button aria-current={view === 'torrents' ? 'page' : undefined} onClick={() => setView('torrents')}>
          Torrents
        </button>
        <button aria-current={view === 'slots' ? 'page' : undefined} onClick={() => setView('slots')}>
          Slots
        </button>
        <div style={{ marginTop: 20 }}>
          <button
            onClick={async () => {
              await api.post('/api/logout').catch(() => {})
              setAuthed(false)
            }}
            className="muted small"
          >
            Sign out
          </button>
        </div>
      </nav>
      <main>
        {view === 'pool' && <Pool />}
        {view === 'torrents' && <Torrents />}
        {view === 'slots' && <Slots />}
      </main>
    </div>
  )
}
