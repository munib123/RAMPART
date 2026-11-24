#!/usr/bin/env node
/**
 * Frontend bundle guard (S6).
 *
 *  - fails if any emitted JS chunk exceeds a generous raw budget, so a regression that
 *    re-eager-imports a page or pulls in a heavy dependency is caught without a size diff;
 *  - fails if a page that `App.tsx` lazy-imports did not produce its own chunk, which is the
 *    route-splitting acceptance item from S4.
 *
 * Run from the repo root (after `npm run build`):
 *     node scripts/check-bundle.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ASSETS = join(ROOT, 'frontend', 'dist', 'assets');
const APP = join(ROOT, 'frontend', 'src', 'App.tsx');
const MAX_CHUNK_BYTES = 600 * 1024; // 600 KiB raw; the current largest chunk is react at ~189 kB.

function fail(message) {
  console.error(`check-bundle: ${message}`);
  process.exit(1);
}

let files;
try {
  files = readdirSync(ASSETS).filter((name) => name.endsWith('.js'));
} catch {
  fail(`no build output at ${ASSETS} - run "npm run build" in frontend/ first`);
}

const sizeOf = (name) => statSync(join(ASSETS, name)).size;
const chunks = files
  .map((name) => ({ name, bytes: sizeOf(name) }))
  .sort((a, b) => b.bytes - a.bytes);

if (chunks.length === 0) fail('no JavaScript chunks were emitted');

const oversized = chunks.filter((chunk) => chunk.bytes > MAX_CHUNK_BYTES);
if (oversized.length > 0) {
  for (const chunk of oversized) {
    const kib = (chunk.bytes / 1024).toFixed(1);
    console.error(`  ${chunk.name}: ${kib} KiB > ${MAX_CHUNK_BYTES / 1024} KiB budget`);
  }
  fail(`${oversized.length} chunk(s) exceeded the size budget`);
}

let appSource;
try {
  appSource = readFileSync(APP, 'utf8');
} catch {
  fail(`cannot read ${APP}`);
}

const lazyPages = [
  ...appSource.matchAll(/import\(\s*['"](?:@|\.{1,2})\/pages\/([^'"]+)['"]\s*\)/g),
].map((match) => match[1].split(/[\\/]/).pop());

if (lazyPages.length === 0) {
  fail('App.tsx has no lazy page imports - route splitting was removed');
}

const emitted = new Set(files);
const missing = lazyPages.filter(
  (page) => ![...emitted].some((name) => name.startsWith(`${page}-`)),
);
if (missing.length > 0) {
  fail(`no chunk emitted for lazy page(s): ${missing.join(', ')}`);
}

const kib = (bytes) => (bytes / 1024).toFixed(1);
console.log(
  `check-bundle: ${chunks.length} JS chunks, largest ${chunks[0].name} ${kib(chunks[0].bytes)} KiB ` +
    `(budget ${MAX_CHUNK_BYTES / 1024} KiB); ${lazyPages.length}/${lazyPages.length} lazy pages split`,
);
