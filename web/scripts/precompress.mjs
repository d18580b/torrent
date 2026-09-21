// Precompress the built bundle, so the daemon can serve a compressed body
// without compressing anything at request time.
//
// The daemon embeds `web/dist` into the binary and negotiates on
// Accept-Encoding: if a `.br` or `.gz` sibling is present it sends that, and
// otherwise it sends the original. Producing them here rather than in the Rust
// build keeps it to Node's built-in zlib — no new dependency on either side —
// and means the cost is paid once per build instead of once per cold client.
//
// Only files that actually shrink are written: a compressed copy that is
// larger than the original is embedded weight for nothing.

import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { brotliCompressSync, constants, gzipSync } from 'node:zlib'

const DIST = new URL('../dist/', import.meta.url).pathname
// A floor, not a packet's worth. At 1024 the one document that matters most
// was excluded: Vite's index.html is typically well under a kilobyte, and it
// is the only file served `Cache-Control: no-cache`, so it is the one
// re-fetched on every cold load. Below a couple of hundred bytes the
// shrink-only guard below would be doing all the work anyway, so the floor
// stays — it is just in the right place now.
const MIN_BYTES = 256
// No `map`. A browser fetches a sourcemap only with devtools open, so a .br
// and a .gz copy of every one is embedded weight in every deployed binary for
// a request almost nobody makes.
const COMPRESSIBLE = /\.(html|css|js|mjs|json|svg|txt|xml)$/i

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry)
    if (statSync(path).isDirectory()) yield* walk(path)
    else yield path
  }
}

let written = 0
let savedBytes = 0

for (const path of walk(DIST)) {
  if (!COMPRESSIBLE.test(path)) continue
  const raw = readFileSync(path)
  if (raw.length < MIN_BYTES) continue

  const variants = [
    ['.br', brotliCompressSync(raw, {
      params: {
        [constants.BROTLI_PARAM_QUALITY]: 11,
        [constants.BROTLI_PARAM_SIZE_HINT]: raw.length,
      },
    })],
    ['.gz', gzipSync(raw, { level: 9 })],
  ]

  for (const [suffix, body] of variants) {
    if (body.length >= raw.length) continue
    writeFileSync(path + suffix, body)
    written++
    savedBytes += raw.length - body.length
  }
}

console.log(
  `precompress: wrote ${written} file(s), ${(savedBytes / 1024).toFixed(1)} KiB smaller in total`,
)
