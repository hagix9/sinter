// Fail-closed consistency gate for the website WebMCP data files.
//
// Read-only: validates that the hand-curated machine-readable sources stay
// in sync with the actual Starlight content tree and the crate version.
// Exits non-zero with actionable diagnostics on any inconsistency.
//
// Run: node scripts/check-webmcp.mjs   (from docs-site/)

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(root, '..');
const docsDir = join(root, 'src/content/docs');
const dataDir = join(root, 'src/data');
const LOCALES = ['en', 'ja'];

let failures = 0;
function fail(msg) {
  failures++;
  console.error(`FAIL  ${msg}`);
}
function ok(msg) {
  console.log(`ok    ${msg}`);
}

function readJson(rel) {
  const p = join(root, rel);
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch (e) {
    fail(`${rel}: invalid JSON (${e.message})`);
    return null;
  }
}

// --- content tree -----------------------------------------------------------

// Map a content file to its index path identity.
//   en/index.mdx          -> ''
//   en/guides/ubuntu.md   -> 'guides/ubuntu'
function contentFiles(locale) {
  const base = join(docsDir, locale);
  const out = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir)) {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) {
        walk(p);
      } else if (/\.mdx?$/.test(e)) {
        const rel = p.slice(base.length + 1).replace(/\.mdx?$/, '');
        out.push(rel === 'index' ? '' : rel);
      }
    }
  };
  if (existsSync(base)) walk(base);
  return out;
}

// --- load sources -----------------------------------------------------------

const resources = readJson('src/data/resources.json');
const resourcesJa = readJson('src/data/resources.ja.json');
const indexes = {
  en: readJson('src/data/doc-index.json'),
  ja: readJson('src/data/doc-index.ja.json'),
};

// 6.1 schema basics ----------------------------------------------------------

if (resources) {
  if (typeof resources.version !== 'string') fail('resources.json: missing string "version"');
  if (!Array.isArray(resources.resourceTypes)) fail('resources.json: missing "resourceTypes" array');
  else {
    for (const r of resources.resourceTypes) {
      for (const f of ['type', 'summary', 'docPath']) {
        if (typeof r[f] !== 'string' || !r[f]) fail(`resources.json: resource missing "${f}": ${JSON.stringify(r.type)}`);
      }
      if (!Array.isArray(r.parameters)) fail(`resources.json: ${r.type}: missing "parameters" array`);
      else {
        for (const p of r.parameters) {
          for (const f of ['name', 'type', 'description']) {
            if (typeof p[f] !== 'string' || !p[f]) fail(`resources.json: ${r.type}: parameter missing "${f}": ${JSON.stringify(p.name)}`);
          }
          if (typeof p.required !== 'boolean') fail(`resources.json: ${r.type}.${p.name}: "required" must be boolean`);
          if (!('default' in p)) fail(`resources.json: ${r.type}.${p.name}: missing "default" field`);
        }
      }
    }
    ok(`resources.json: ${resources.resourceTypes?.length ?? 0} resource types validated`);
  }
}

if (resourcesJa) {
  if (resourcesJa.locale !== 'ja') fail('resources.ja.json: "locale" must be "ja"');
  if (typeof resourcesJa.resourceTypes !== 'object' || resourcesJa.resourceTypes === null || Array.isArray(resourcesJa.resourceTypes)) {
    fail('resources.ja.json: "resourceTypes" must be an overlay map keyed by type');
  }
}

for (const loc of LOCALES) {
  const idx = indexes[loc];
  if (!idx) continue;
  if (!Array.isArray(idx.pages)) {
    fail(`doc-index${loc === 'ja' ? '.ja' : ''}.json: missing "pages" array`);
    continue;
  }
  for (const p of idx.pages) {
    for (const f of ['title', 'path', 'description', 'keywords']) {
      if (typeof p[f] !== 'string') fail(`doc-index.${loc}: page entry missing string "${f}": ${JSON.stringify(p.path)}`);
    }
  }
}

// 6.2/6.3/6.4 index path existence, locale correctness, duplicates -----------

const contentByLocale = {};
for (const loc of LOCALES) {
  contentByLocale[loc] = new Set(contentFiles(loc));
  const idx = indexes[loc];
  if (!idx?.pages) continue;

  const seen = new Set();
  for (const p of idx.pages) {
    if (typeof p.path !== 'string') continue;
    if (seen.has(p.path)) fail(`doc-index.${loc}: duplicate path "${p.path}"`);
    seen.add(p.path);
    // Locale correctness: an index for <loc> must reference <loc> content only.
    if (LOCALES.some((l) => l !== loc && (p.path === l || p.path.startsWith(l + '/')))) {
      fail(`doc-index.${loc}: path "${p.path}" carries a foreign locale prefix`);
    }
    if (!contentByLocale[loc].has(p.path)) {
      fail(`doc-index.${loc}: path "${p.path}" does not resolve to src/content/docs/${loc}/${p.path || 'index'}.(md|mdx)`);
    }
  }

  // Completeness: doc-index is the site's page index (it also drives the
  // legacy redirects), so every content page must be indexed.
  for (const c of contentByLocale[loc]) {
    if (!seen.has(c)) {
      fail(`doc-index.${loc}: content page "${c || '(home)'}" is not indexed`);
    }
  }
  ok(`doc-index.${loc}: ${seen.size} entries, all resolve`);
}

// 6.5 resource docPath existence (canonical English docs) --------------------

if (resources?.resourceTypes) {
  const seenTypes = new Set();
  for (const r of resources.resourceTypes) {
    if (seenTypes.has(r.type)) fail(`resources.json: duplicate resource type "${r.type}"`);
    seenTypes.add(r.type);
    if (typeof r.docPath === 'string' && !contentByLocale.en?.has(r.docPath)) {
      fail(`resources.json: ${r.type}.docPath "${r.docPath}" does not resolve to an English doc page`);
    }
  }
  ok('resources.json: docPaths and type identities validated');
}

// 6.6 release consistency — Cargo.toml [package] version is authoritative ----

const cargo = readFileSync(join(repo, 'Cargo.toml'), 'utf8');
const cargoVersion = cargo.match(/\[package\][^[]*?\bversion\s*=\s*"([^"]+)"/s)?.[1];
if (!cargoVersion) {
  fail('Cargo.toml: could not determine [package] version');
} else {
  if (resources && resources.version !== cargoVersion) {
    fail(`resources.json: version "${resources.version}" != Cargo.toml version "${cargoVersion}"`);
  }
  const builder = readFileSync(join(dataDir, 'build-webmcp.ts'), 'utf8');
  const release = builder.match(/\brelease:\s*'([^']+)'/)?.[1];
  if (release !== `v${cargoVersion}`) {
    fail(`build-webmcp.ts: installation.release "${release}" != "v${cargoVersion}" (Cargo.toml)`);
  }
  for (const m of builder.matchAll(/'(sinter-v[^']*\.tar\.gz)'/g)) {
    if (m[1] !== `sinter-v${cargoVersion}-linux-x86_64.tar.gz`) {
      fail(`build-webmcp.ts: artifact "${m[1]}" != "sinter-v${cargoVersion}-linux-x86_64.tar.gz"`);
    }
  }
  ok(`release consistency: resources.version/build-webmcp.ts match Cargo.toml ${cargoVersion}`);
}

// 6.7 EN/JA structural parity -------------------------------------------------

if (indexes.en?.pages && indexes.ja?.pages) {
  const enPaths = indexes.en.pages.map((p) => p.path).sort();
  const jaPaths = indexes.ja.pages.map((p) => p.path).sort();
  const onlyEn = enPaths.filter((p) => !jaPaths.includes(p));
  const onlyJa = jaPaths.filter((p) => !enPaths.includes(p));
  for (const p of onlyEn) fail(`doc-index parity: "${p}" indexed in en but not ja`);
  for (const p of onlyJa) fail(`doc-index parity: "${p}" indexed in ja but not en`);
  if (!onlyEn.length && !onlyJa.length) ok('doc-index parity: en/ja index identical page sets');
}

if (resources?.resourceTypes && resourcesJa?.resourceTypes) {
  const enTypes = new Map(resources.resourceTypes.map((r) => [r.type, r]));
  for (const [type, ov] of Object.entries(resourcesJa.resourceTypes)) {
    const en = enTypes.get(type);
    if (!en) {
      fail(`resources.ja.json: overlay type "${type}" has no English resource type`);
      continue;
    }
    const enParams = new Set(en.parameters.map((p) => p.name));
    for (const name of Object.keys(ov.parameters ?? {})) {
      if (!enParams.has(name)) fail(`resources.ja.json: overlay parameter "${type}.${name}" has no English parameter`);
    }
  }
  ok('resources.ja.json: overlay keys all backed by English definitions');
}

// --- verdict -----------------------------------------------------------------

if (failures) {
  console.error(`\nwebmcp:check FAILED — ${failures} inconsistency(ies)`);
  process.exit(1);
}
console.log('\nwebmcp:check OK');
