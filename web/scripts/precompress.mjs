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
// Below roughly a packet's worth, compression is noise.
const MIN_BYTES = 1024
const COMPRESSIBLE = /\.(html|css|js|mjs|json|svg|map|txt|xml)$/i

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
