// Air-gap guard (spec §25.19): fails if the production build could load anything from another origin.
//  1. index.html may only reference same-origin assets (no CDN scripts, styles or fonts).
//  2. Built JS/CSS may only contain URL strings for hosts on the allowlist below. These are XML namespace
//     identifiers, library error/documentation messages and UI placeholders: strings, never fetched.
// Usage: node scripts/check-offline-bundle.mjs [distDir]
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const dist = process.argv[2] || 'dist'
const ALLOWED_HOSTS = new Set([
  'www.w3.org', // SVG / XHTML / MathML / XLink namespaces
  'localhost', // URL parsing base in libraries
  'fb.me', 'reactjs.org', 'reactrouter.com', 'github.com', // dev/error message links inside libraries
])
const ALLOWED_SUFFIXES = ['.example'] // RFC 2606 placeholders shown in form hints

const failures = []

const html = readFileSync(join(dist, 'index.html'), 'utf8')
for (const [, attr, value] of html.matchAll(/\b(src|href)\s*=\s*["']([^"']+)["']/g)) {
  if (/^(https?:)?\/\//i.test(value)) failures.push(`index.html ${attr}="${value}" is not same-origin`)
}

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(e => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]))
}

for (const file of walk(dist).filter(f => /\.(js|css|html)$/.test(f))) {
  const text = readFileSync(file, 'utf8')
  for (const [url, host] of text.matchAll(/https?:\/\/([a-zA-Z0-9.-]+)/g)) {
    const h = host.toLowerCase().replace(/\.$/, '')
    if (ALLOWED_HOSTS.has(h) || ALLOWED_SUFFIXES.some(s => h.endsWith(s))) continue
    failures.push(`${file}: unexpected external URL ${url}`)
  }
  if (/@import\s+url\(\s*["']?(https?:)?\/\//i.test(text)) failures.push(`${file}: external CSS @import`)
}

if (failures.length) {
  console.error(`Offline bundle check FAILED (${failures.length}):\n  ` + [...new Set(failures)].join('\n  '))
  process.exit(1)
}
console.log('Offline bundle check passed: no external origins in the build.')
