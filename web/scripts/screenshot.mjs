// Screenshot the pool browser against a mocked API.
//
// The point is a README image that stays honest as the UI changes, without
// needing a daemon, libtorrent, the submodules, or a config file. Every
// request the client makes is a same-origin `fetch` from one wrapper in
// web/src/lib/api.ts, so intercepting `**/api/**` covers all of it and the app
// needs no build-time changes.
//
//   mise run screenshot
//
// Writes docs/img/pool.png.

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { extname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from '@playwright/test'

const repo = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const dist = join(repo, 'web', 'dist')
const out = join(repo, 'docs', 'img', 'pool.png')
const fixture = JSON.parse(
  await readFile(join(repo, 'web', 'fixtures', 'pool.json'), 'utf8'),
)

if (!existsSync(join(dist, 'index.html'))) {
  console.error('web/dist is not built. Run: npm --prefix web ci && npm --prefix web run build')
  process.exit(1)
}

const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.svg': 'image/svg+xml', '.json': 'application/json', '.ico': 'image/x-icon',
}

// vite.config.ts sets no `base`, so assets are absolute `/assets/*` and the
// bundle serves unmodified from any static root.
const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost')
  const file = join(dist, url.pathname === '/' ? 'index.html' : url.pathname)
  try {
    const body = await readFile(file)
    res.writeHead(200, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' })
    res.end(body)
  } catch {
    // SPA fallback, matching how the daemon serves the client.
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(await readFile(join(dist, 'index.html')))
  }
})

await new Promise((r) => server.listen(0, '127.0.0.1', r))
const base = `http://127.0.0.1:${server.address().port}`

const browser = await chromium.launch()
const page = await browser.newPage({
  viewport: { width: 1280, height: 720 },
  deviceScaleFactor: 2,
  colorScheme: 'dark',
})

await page.route('**/api/**', async (route) => {
  const path = new URL(route.request().url()).pathname
  // The SSE stream never completes, so it has to be aborted explicitly or
  // nothing that waits on network idle will ever resolve.
  if (path === '/api/events') return route.abort()
  const body = fixture[path]
  if (body === undefined) return route.fulfill({ status: 404, body: '{}' })
  return route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(body),
  })
})

// `#/pool` is the landing view; the client routes on the fragment because the
// pre-`/api` compatibility aliases make `/pool` a real API path.
await page.goto(`${base}/#/pool`, { waitUntil: 'networkidle' })
// Wait for real content rather than a timeout: the tree only renders once the
// overview has resolved a root id.
await page.getByText('debian', { exact: false }).first().waitFor({ timeout: 15_000 })

await page.screenshot({ path: out })
console.log(`wrote ${out}`)

await browser.close()
server.close()
