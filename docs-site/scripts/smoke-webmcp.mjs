// Deployed-site WebMCP/discovery acceptance check (read-only, GET only).
//
// Verifies the LIVE GitHub Pages deployment serves the human docs, the
// machine-readable WebMCP payloads, the browser tool script, and the
// discovery files — plus the semantic invariants (current release, platform
// matrix, hedged Oracle status).
//
// Usage: node scripts/smoke-webmcp.mjs [base-url]
//   default base: https://hagix9.github.io/sinter

const base = (process.argv[2] ?? 'https://hagix9.github.io/sinter').replace(/\/+$/, '');

let failures = 0;
const fail = (m) => { failures++; console.error(`FAIL  ${m}`); };
const ok = (m) => console.log(`ok    ${m}`);

async function get(path) {
  const url = base + path;
  const r = await fetch(url);
  return { url, status: r.status, type: r.headers.get('content-type') ?? '', body: await r.text() };
}

async function expectOk(path, typeRe) {
  const { url, status, type, body } = await get(path);
  if (status !== 200) { fail(`${url}: HTTP ${status}`); return null; }
  if (typeRe && !typeRe.test(type)) { fail(`${url}: unexpected content-type "${type}"`); return null; }
  ok(`${url}: 200 ${type}`);
  return body;
}

// 18.1 human docs
await expectOk('/en/', /text\/html/);
await expectOk('/en/reference/webmcp/', /text\/html/);
await expectOk('/ja/', /text\/html/);

// 18.3 browser script + injection on a rendered page
const script = await expectOk('/webmcp.js', /javascript/);
if (script && !script.includes('modelContext')) fail('/webmcp.js: does not reference modelContext');
const home = await get('/en/');
if (home.status === 200 && !home.body.includes(`${base.replace(/^https?:\/\/[^/]+/, '')}/webmcp.js`)) {
  fail('/en/: rendered page does not load /webmcp.js');
} else if (home.status === 200) ok('/en/: webmcp.js script tag present');

// 18.2 machine-readable payloads
const payloads = {};
for (const p of ['/webmcp/en.json', '/webmcp/ja.json', '/webmcp.json']) {
  const body = await expectOk(p, /application\/json/);
  try {
    if (body) payloads[p] = JSON.parse(body);
  } catch {
    fail(`${base}${p}: invalid JSON`);
  }
}

// 18.2 semantic invariants
const en = payloads['/webmcp/en.json'];
const ja = payloads['/webmcp/ja.json'];
const root = payloads['/webmcp.json'];
if (en) {
  if (en.locale !== 'en') fail('en.json: locale != "en"');
  if (en.version !== '0.4.1') fail(`en.json: version "${en.version}" != 0.4.1`);
  if (en.installation?.release !== 'v0.4.1') fail(`en.json: installation.release "${en.installation?.release}" != v0.4.1`);
  const plats = en.compatibility?.platforms ?? [];
  const tested = plats.filter((p) => p.status === 'supported, acceptance-tested');
  if (tested.length !== 8) fail(`en.json: ${tested.length} acceptance-tested platforms (expected 8)`);
  const oracle = plats.find((p) => /oracle/i.test(p.name));
  if (!oracle || !/not acceptance-tested/i.test(oracle.status)) {
    fail(`en.json: Oracle Linux status "${oracle?.status}" not correctly hedged`);
  }
  if (!en.pages?.some((p) => p.path === 'en/reference/webmcp')) {
    fail('en.json: reference/webmcp missing from index');
  }
  const names = plats.map((p) => p.name).join(', ');
  for (const n of ['Ubuntu 24.04 LTS', 'Ubuntu 26.04 LTS', 'Rocky Linux 9', 'Rocky Linux 10', 'RHEL 9', 'RHEL 10', 'AlmaLinux 9', 'AlmaLinux 10', 'Oracle Linux']) {
    if (!names.includes(n)) fail(`en.json: platform "${n}" missing`);
  }
  ok('en.json: release/platform/Oracle/index invariants hold');
}
if (ja) {
  if (ja.locale !== 'ja') fail('ja.json: locale != "ja"');
  if (ja.version !== en?.version) fail('ja.json: version differs from en.json');
  if (!ja.pages?.some((p) => p.path === 'ja/reference/webmcp')) fail('ja.json: reference/webmcp missing');
  if (!ja.compatibility?.platforms?.some((p) => /oracle/i.test(p.name) && /not acceptance-tested/i.test(p.status))) {
    fail('ja.json: Oracle status missing/altered');
  }
  ok('ja.json: locale/version/index/Oracle invariants hold');
}
if (root && en && JSON.stringify(root) !== JSON.stringify(en)) {
  fail('webmcp.json: default payload differs from en.json');
} else if (root) ok('webmcp.json: identical to en.json');

// 18.4 discovery files
const llms = await expectOk('/llms.txt', /text\/plain/);
if (llms) {
  for (const bad of ['localhost', '127.0.0.1', 'file://', '/Users/', 'v0.4.0']) {
    if (llms.includes(bad)) fail(`llms.txt: contains "${bad}"`);
  }
  if (!llms.includes(`${base}/en/`)) fail('llms.txt: missing canonical docs URL');
}
const robots = await expectOk('/robots.txt', /text\/plain/);
if (robots) {
  if (!/Sitemap:\s*https:\/\/hagix9\.github\.io\/sinter\/sitemap-index\.xml/.test(robots)) {
    fail('robots.txt: sitemap reference missing/incorrect');
  }
  if (/Disallow:\s*\/sinter\/?\s*$/m.test(robots)) fail('robots.txt: blocks the documentation site');
}

// 18.5 sitemap
const sm = await expectOk('/sitemap-index.xml', /xml/);
if (sm && !sm.includes('sitemap')) fail('sitemap-index.xml: unexpected content');

// no private/internal leakage in public payloads
const blob = JSON.stringify(payloads);
for (const bad of ['/Users/', 'CAND', 'FAILED', 'staging', '.bin', 'SHA256SUMS.failed']) {
  if (blob.includes(bad)) fail(`payloads: contain internal marker "${bad}"`);
}

console.log(failures ? `\nwebmcp:smoke FAILED — ${failures} failure(s)` : '\nwebmcp:smoke OK — all live checks passed');
process.exit(failures ? 1 : 0);
