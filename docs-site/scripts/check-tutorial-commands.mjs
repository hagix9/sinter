// Consistency gate for the OpenStack all-in-one tutorial
// (src/content/docs/{en,ja}/tutorials/openstack-aio/*.mdx).
//
// Read-only. It checks the commands, not the prose: commands go in ```sh
// blocks (other shell fences and unlabelled blocks are rejected), and for
// every one of them that:
//   - the block names the host it runs on (a known `title="…"`);
//   - `bash -n` accepts it;
//   - English and Japanese pages carry the same commands on the same hosts,
//     the same evidence labels and the same numbers in the prose;
//   - the recipe files, options, OpenStack object names, target paths and
//     systemd units it uses exist in examples/openstack as whole names (and
//     the sinter options exist in src/main.rs); runs against the AIO node
//     pass --host/--user/--identity/--sudo; builder.yaml runs as root;
//   - each command runs on its host (sinter and the RPM/secret tools on the
//     builder, openstack/virsh/ip netns as root on the AIO node), and every
//     variable a block reads is set in it, earlier on the page, or by
//     `. ~/sinter-os.env` in the same block;
//   - every IPv4 literal is a synthetic or well-known value.
// The sample outputs: each `sinter validate` has its `ok: …` sample, and the
// plan/apply/audit summaries add up and match that recipe's resource count.
// With SINTER_BIN=<path to a sinter binary> it also runs `sinter validate`
// and compares the samples with the real output. The commit the tutorial
// checks out must be an ancestor of HEAD with the same examples/openstack
// (skipped in a shallow clone unless TUTORIAL_REQUIRE_PIN=1).
//
// Run: node scripts/check-tutorial-commands.mjs   (from docs-site/)

import { readFileSync, readdirSync, existsSync, mkdtempSync, cpSync, rmSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(root, '..');
const recipeDir = join(repo, 'examples/openstack');
const PAGES_DIR = 'src/content/docs/{locale}/tutorials/openstack-aio';
const LOCALES = ['en', 'ja'];

// The host of a block, by locale. The same key must appear in both languages.
export const HOSTS = {
  en: {
    'Your terminal': 'terminal',
    Builder: 'builder',
    'Builder (inside tmux)': 'builder',
    'AIO node': 'aio',
    'AIO node (root)': 'aio-root',
  },
  ja: {
    操作端末: 'terminal',
    ビルダー: 'builder',
    'ビルダー（tmux の中）': 'builder',
    'AIO サーバー': 'aio',
    'AIO サーバー（root）': 'aio-root',
  },
};

// IPv4 literals the tutorial may show: synthetic examples (site.yaml's
// defaults, RFC 5737), loopback and the masks of `ip addr` samples.
export const ALLOWED_IPV4 = new Set(['10.0.0.10', '127.0.0.1', '192.0.2.0', '192.0.2.1']);

// --- extraction ---------------------------------------------------------------

/** Fenced code blocks of an MDX page: { lang, title, code, line }. */
export function codeBlocks(text) {
  const out = [];
  const re = /^```([A-Za-z0-9_-]*)([^\n]*)\n([\s\S]*?)^```[ \t]*$/gm;
  let m;
  while ((m = re.exec(text))) {
    const title = m[2].match(/title="([^"]*)"/)?.[1] ?? null;
    const line = text.slice(0, m.index).split('\n').length;
    out.push({ lang: m[1], title, code: m[3], line });
  }
  return out;
}

/** The commands of a shell block without comments and placeholder text, for EN/JA comparison. */
export function normalizeShell(code) {
  return code
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .map((l) => l.replace(/\s{2,}#\s.*$/, '').replace(/<[^<>\n]*>/g, '<>').trimEnd())
    .filter((l) => l !== '')
    .join('\n');
}

export function bashSyntaxError(code) {
  const r = spawnSync('bash', ['-n'], { input: code, encoding: 'utf8' });
  if (r.error) return `bash not runnable: ${r.error.message}`;
  return r.status === 0 ? null : (r.stderr || 'bash -n failed').trim();
}

/** Long options a shell script accepts in its `case "$1" in` parser. */
export function scriptOptions(script) {
  return new Set([...script.matchAll(/^\s*(--[a-z][a-z-]*)(?:\|-[a-z])?\)/gm)].map((m) => m[1]));
}

/** Long options that clap derives from src/main.rs. */
export function sinterOptions(mainRs) {
  const opts = new Set(['--help', '--version']);
  const re = /#\[arg\(([^\]]*)\)\]\s*(?:\/\/\/[^\n]*\n\s*)*(?:pub\s+)?([a-z_]+)\s*:/g;
  let m;
  while ((m = re.exec(mainRs))) {
    if (!/\blong\b/.test(m[1])) continue;
    const explicit = m[1].match(/long\s*=\s*"([^"]+)"/)?.[1];
    opts.add(`--${explicit ?? m[2].replace(/_/g, '-')}`);
    for (const a of m[1].matchAll(/visible_alias\s*=\s*"([^"]+)"/g)) opts.add(`--${a[1]}`);
  }
  return opts;
}

// --- checks -------------------------------------------------------------------

// Fences that hold shell commands but would escape the checks if they were allowed.
export const SHELL_LIKE = new Set(['bash', 'shell', 'console', 'zsh', 'sh-session', 'shellscript', 'terminal']);
// The recipe whose run a page's sample summaries show.
const RECIPE_OF_PAGE = { 'build-rpms': 'builder.yaml', deploy: 'all-in-one.yaml', verify: 'all-in-one.yaml' };
const SINTER_RECIPES = ['builder.yaml', 'all-in-one.yaml'];

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** `w` occurs in `text` as a whole name (not as a prefix or suffix of a longer name). */
export const hasWord = (text, w) => new RegExp(`(?:^|[^\\w-])${esc(w)}(?![\\w-])`, 'm').test(text);
const outsideCode = (text) => text.replace(/^```[\s\S]*?^```[ \t]*$/gm, '');

export function checkPage({ locale, name, text }, ctx, fail) {
  const where = (b) => `${locale}/${name}.mdx:${b.line}`;
  const shells = [];
  const defined = new Set(); // shell variables set by earlier blocks of the page
  for (const b of codeBlocks(text)) {
    for (const ip of b.code.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? []) {
      if (!ALLOWED_IPV4.has(ip)) fail(`${where(b)}: IPv4 literal ${ip} is not an allowed synthetic value`);
    }
    if (SHELL_LIKE.has(b.lang)) fail(`${where(b)}: use \`\`\`sh for commands (\`\`\`${b.lang} is not checked)`);
    if (b.lang === '') fail(`${where(b)}: code block without a language (use sh for commands, text for output)`);
    if (b.lang !== 'sh') continue;
    const host = b.title === null ? undefined : HOSTS[locale][b.title];
    if (!host) fail(`${where(b)}: shell block needs a host title (one of ${Object.keys(HOSTS[locale]).join(', ')}), got ${JSON.stringify(b.title)}`);
    const err = bashSyntaxError(b.code);
    if (err) fail(`${where(b)}: bash -n: ${err}`);
    checkCommands(b, ctx, (msg) => fail(`${where(b)}: ${msg}`));
    if (host) checkHostAndVars(b, host, defined, (msg) => fail(`${where(b)}: ${msg}`));
    shells.push({ host, code: normalizeShell(b.code), line: b.line });
  }
  for (const ip of outsideCode(text).match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? []) {
    if (!ALLOWED_IPV4.has(ip)) fail(`${locale}/${name}.mdx: IPv4 literal ${ip} in prose is not an allowed synthetic value`);
  }
  return shells;
}

// Which host a command belongs to. A rule's pattern must not appear in a block of another host.
export const HOST_RULES = [
  [/(?:^|[\s;|&(/])sinter[ \t]+(?:validate|plan|apply|audit)\b/m, ['builder'], 'sinter runs on the builder'],
  [/stage-rpm-repo\.sh|gen-secrets\.sh|rpmbuild/, ['builder'], 'the RPM and secret tools run on the builder'],
  [/(?:^|[\s;|&(])(?:openstack|virsh|ovn-sbctl)\s|ip netns|admin-openrc|secrets\.env/m, ['aio-root'], 'OpenStack commands run as root on the AIO node'],
];
// Variables a block may use without setting them.
const ENV_FILE_VARS = new Set(['AIO_IP', 'AIO_HOSTNAME', 'SSH_KEY']);
const AMBIENT_VARS = new Set(['HOME', 'USER', 'PWD', 'PIPESTATUS', 'PATH']);

/** Host rules, and every variable a block reads is set in it, in an earlier block of the page, or by `. ~/sinter-os.env`. */
export function checkHostAndVars(block, host, defined, fail) {
  const code = block.code;
  for (const [re, hosts, why] of HOST_RULES) {
    if (re.test(code) && !hosts.includes(host)) fail(`runs on ${host}, but ${why}`);
  }
  const sources = /(?:^|[\s;&(])\.\s+~\/sinter-os\.env\b/m.test(code);
  // remote commands of ssh '…' and the heredoc that writes the env file are not evaluated here
  const local = code.replace(/<<'EOF'\n[\s\S]*?\nEOF\n/g, '\n');
  const sets = new Set([
    ...[...local.matchAll(/(?:^|[\s;&('"])([A-Za-z_][A-Za-z0-9_]*)=/gm)].map((m) => m[1]),
    ...[...local.matchAll(/\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b/g)].map((m) => m[1]),
  ]);
  for (const m of local.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/g)) {
    const v = m[1];
    if (sets.has(v) || defined.has(v) || AMBIENT_VARS.has(v)) continue;
    if (ENV_FILE_VARS.has(v)) {
      if (!sources) fail(`uses $${v} without \`. ~/sinter-os.env\` in the same block`);
      continue;
    }
    fail(`uses $${v}, which no earlier block of the page sets`);
  }
  for (const v of sets) defined.add(v);
}

export function checkCommands(block, ctx, fail) {
  const code = block.code.replace(/\\\n/g, ' ');
  // recipe files run from examples/openstack
  for (const m of code.matchAll(/(?:^|[\s;|&(])((?:tools|files|components|templates)\/[\w./-]+|[\w-]+\.yaml)\b/gm)) {
    const f = m[1];
    if (!ctx.recipeFiles.has(f)) fail(`recipe file ${f} does not exist in examples/openstack`);
  }
  // options of stage-rpm-repo.sh
  for (const m of code.matchAll(/stage-rpm-repo\.sh([^\n;|&]*)/g)) {
    for (const o of m[1].match(/--[a-z][a-z-]*/g) ?? []) {
      if (!ctx.stageOptions.has(o)) fail(`tools/stage-rpm-repo.sh has no option ${o}`);
    }
  }
  // sinter subcommands and options
  for (const m of code.matchAll(/(?:^|[\s;|&(/])sinter[ \t]+([a-z]+)([^\n;|&]*)/gm)) {
    if (!['validate', 'plan', 'apply', 'audit'].includes(m[1])) {
      fail(`unexpected sinter subcommand ${m[1]}`);
    }
    for (const o of m[2].match(/--[a-z][a-z-]*/g) ?? []) {
      if (!ctx.sinterOptions.has(o)) fail(`sinter has no option ${o}`);
    }
  }
  // runs against the AIO node go over SSH and need root there
  for (const m of code.matchAll(/(?:^|[\s;|&(/])sinter[ \t]+(plan|apply|audit)[ \t]+all-in-one\.yaml([^\n;|&]*)/gm)) {
    for (const o of ['--host', '--user', '--identity', '--sudo']) {
      if (!new RegExp(`(?:^|\\s)${o}(?=\\s|$)`).test(m[2])) fail(`sinter ${m[1]} all-in-one.yaml must pass ${o}`);
    }
  }
  // builder.yaml runs locally as root, by the full path (sudo's PATH has no /usr/local/bin)
  for (const line of code.split('\n')) {
    if (/(?:^|[\s/])sinter[ \t]+(?:plan|apply)[ \t]+builder\.yaml/.test(line) && !/sudo env HOME=\/root \/usr\/local\/bin\/sinter (?:plan|apply) builder\.yaml/.test(line)) {
      fail('sinter plan/apply builder.yaml must run as `sudo env HOME=/root /usr/local/bin/sinter …`');
    }
  }
  // OpenStack objects the recipe creates (whole names)
  for (const [flag, kind] of [['--flavor', 'flavor'], ['--image', 'image'], ['--network', 'network'], ['--key-name', 'key pair']]) {
    for (const m of code.matchAll(new RegExp(`${flag}\\s+([\\w.-]+)`, 'g'))) {
      if (!hasWord(ctx.recipeText, m[1])) fail(`${kind} ${m[1]} is not created by the recipe`);
    }
  }
  // target paths the recipe owns: the directory as a whole path, the file name as a whole name
  for (const m of code.matchAll(/(\/(?:etc\/sinter-openstack|opt\/hagistack-[\w-]+|var\/lib\/hagistack-build|root\/rpmbuild))((?:\/[\w.-]+)*)/g)) {
    const [p, dir, rest] = m;
    if (!new RegExp(`${esc(dir)}(?![\\w-])`).test(ctx.recipeText)) fail(`path ${p}: ${dir} does not appear in the recipe`);
    const leaf = basename(rest);
    if (rest && !hasWord(ctx.recipeText, leaf)) fail(`path ${p}: ${leaf} does not appear in the recipe`);
  }
  // systemd units: the reboot loop, systemctl and journalctl arguments
  const units = [];
  for (const m of code.matchAll(/for s in ([^;]*);/g)) units.push(...m[1].split(/\s+/));
  for (const m of code.matchAll(/systemctl[ \t]+(?:is-active|status|restart|start|stop|enable|disable)((?:[ \t]+[^\s;|&]+)+)/g)) units.push(...m[1].split(/\s+/));
  for (const m of code.matchAll(/journalctl[ \t]+-u[ \t]+([^\s;|&]+)/g)) units.push(m[1]);
  for (const unit of units.filter((u) => u && !/^[-$"']/.test(u))) {
    if (!new RegExp(`name:\\s*${esc(unit)}(?:\\.service)?(?![\\w.-])`).test(ctx.recipeText)) {
      fail(`systemd unit ${unit} is not managed by the recipe`);
    }
  }
  // the checked-out Sinter commit must be a full commit id
  for (const m of code.matchAll(/git checkout --detach (\S+)/g)) {
    if (!/^[0-9a-f]{40}$/.test(m[1])) fail(`checkout target ${m[1]} is not a full commit id`);
  }
}

const badges = (text) => [...text.matchAll(/<Badge\s+text="[^"]*"\s+variant="(\w+)"/g)].map((m) => m[1]);
/** Numbers of two or more digits in the prose (outside code blocks and imports). */
export const proseNumbers = (text) =>
  [...new Set(outsideCode(text).replace(/^import .*$/gm, '').match(/\d{2,}/g) ?? [])].sort();

export function checkParity(pages, fail, texts = []) {
  for (const name of Object.keys(pages.en)) {
    const en = pages.en[name];
    const ja = pages.ja[name];
    if (!ja) { fail(`ja/${name}.mdx is missing`); continue; }
    if (en.length !== ja.length) {
      fail(`${name}: en has ${en.length} shell blocks, ja has ${ja.length}`);
      continue;
    }
    en.forEach((b, i) => {
      if (b.host !== ja[i].host) fail(`${name}: shell block ${i + 1} runs on ${b.host} in en (line ${b.line}) but on ${ja[i].host} in ja (line ${ja[i].line})`);
      if (b.code !== ja[i].code) fail(`${name}: shell block ${i + 1} differs between en (line ${b.line}) and ja (line ${ja[i].line})`);
    });
  }
  for (const name of Object.keys(pages.ja)) if (!pages.en[name]) fail(`en/${name}.mdx is missing`);
  // the evidence labels and the numbers in the prose must agree too
  const byKey = new Map(texts.map((t) => [`${t.locale}/${t.name}`, t.text]));
  for (const name of Object.keys(pages.en)) {
    const en = byKey.get(`en/${name}`);
    const ja = byKey.get(`ja/${name}`);
    if (en === undefined || ja === undefined) continue;
    if (badges(en).join() !== badges(ja).join()) fail(`${name}: evidence labels differ: en [${badges(en)}] ja [${badges(ja)}]`);
    const ne = proseNumbers(en);
    const nj = proseNumbers(ja);
    const onlyEn = ne.filter((n) => !nj.includes(n));
    const onlyJa = nj.filter((n) => !ne.includes(n));
    if (onlyEn.length || onlyJa.length) fail(`${name}: numbers in the prose differ: only en [${onlyEn}] only ja [${onlyJa}]`);
  }
}

/** Recipe facts the tutorial states as plain text. */
export function checkRecipeFacts(texts, ctx, fail) {
  const site = ctx.siteYaml;
  // 4-1 edits site.yaml by replacing these literal default values
  const ipLines = [...site.matchAll(/^\s+(\w+):[^\n]*\n\s+value: "10\.0\.0\.10"/gm)].map((m) => m[1]).sort();
  if (JSON.stringify(ipLines) !== JSON.stringify(['controller_ip', 'mgmt_ip'])) {
    fail(`site.yaml: value "10.0.0.10" must belong to exactly mgmt_ip and controller_ip, found ${JSON.stringify(ipLines)}`);
  }
  const hostLines = [...site.matchAll(/^\s+(\w+):[^\n]*\n\s+value: "osdemo1"/gm)].map((m) => m[1]);
  if (JSON.stringify(hostLines) !== JSON.stringify(['os_hostname'])) {
    fail(`site.yaml: value "osdemo1" must belong to exactly os_hostname, found ${JSON.stringify(hostLines)}`);
  }
  const pinned = ctx.builderYaml.match(/hagistack_commit:\s*\{\s*value:\s*"([0-9a-f]{40})"/)?.[1];
  for (const t of texts) {
    for (const h of t.text.match(/\b8225c50c[0-9a-f]{32}\b/g) ?? []) {
      if (h !== pinned) fail(`${t.locale}/${t.name}.mdx: hagistack commit ${h} != builder.yaml ${pinned}`);
    }
  }
}

/**
 * Sample outputs. Every `sinter validate <recipe>` block must be followed by its `ok: …` sample; the
 * summaries shown for a recipe's plan/apply/audit must have that recipe's resource count and add up.
 * With `want` (the real `sinter validate` output per recipe) the samples must equal it.
 */
export function checkSamples(texts, fail, want = null) {
  const shown = {};
  for (const t of texts) {
    const blocks = codeBlocks(t.text);
    blocks.forEach((b, i) => {
      if (b.lang !== 'sh') return;
      const last = b.code.trim().split('\n').pop().trim();
      const m = last.match(/^sinter validate (\S+)$/);
      if (!m) return;
      const next = blocks[i + 1];
      const sample = next && next.lang === 'text' ? next.code.trim().split('\n')[0] : undefined;
      if (!sample || !sample.startsWith('ok: ')) {
        fail(`${t.locale}/${t.name}.mdx:${b.line}: sinter validate ${m[1]} has no "ok: …" sample right after it`);
        return;
      }
      (shown[t.locale] ??= {})[m[1]] = sample;
      if (want && want[m[1]] !== undefined && sample !== want[m[1]]) {
        fail(`${t.locale}/${t.name}.mdx: sample "${sample}" != sinter validate ${m[1]}: "${want[m[1]]}"`);
      }
    });
  }
  for (const locale of Object.keys(shown)) {
    for (const r of SINTER_RECIPES) if (!shown[locale][r]) fail(`${locale}: no sinter validate ${r} sample`);
  }
  for (const t of texts) {
    const recipe = RECIPE_OF_PAGE[t.name];
    const count = Number(shown[t.locale]?.[recipe]?.match(/^ok: (\d+) resource/)?.[1]);
    for (const b of codeBlocks(t.text).filter((x) => x.lang === 'text')) {
      for (const line of b.code.split('\n')) {
        const run = line.match(/^summary: (\d+) changed, (\d+) possible, (\d+) failed, (\d+) indeterminate, (\d+) total$/);
        const audit = line.match(/^summary: (\d+) total, (\d+) compliant, (\d+) drifted, (\d+) not_auditable, (\d+) not_applicable, (\d+) errors$/);
        if (line.startsWith('summary: ') && !run && !audit) fail(`${t.locale}/${t.name}.mdx:${b.line}: unrecognised summary line: ${line}`);
        const nums = (run ?? audit ?? []).slice(1).map(Number);
        if (run && nums.slice(0, 4).reduce((a, x) => a + x, 0) > nums[4]) fail(`${t.locale}/${t.name}.mdx:${b.line}: summary counts exceed the total: ${line}`);
        if (audit && nums.slice(1).reduce((a, x) => a + x, 0) !== nums[0]) fail(`${t.locale}/${t.name}.mdx:${b.line}: audit counts do not add up to the total: ${line}`);
        const total = run ? nums[4] : audit ? nums[0] : undefined;
        if (total !== undefined && !recipe) fail(`${t.locale}/${t.name}.mdx:${b.line}: a summary on a page without a known recipe`);
        if (total !== undefined && recipe && total !== count) fail(`${t.locale}/${t.name}.mdx:${b.line}: ${total} total != ${count} resources of ${recipe}`);
      }
    }
  }
  return shown;
}

const gitRun = (args) => {
  const r = spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8' });
  return { ok: r.status === 0, out: r.stdout ?? '' };
};

/**
 * The commit the tutorial checks out: one full id everywhere, an ancestor of HEAD, with the same
 * examples/openstack as the working tree, and the `git log -1` sample shows its id and subject. When the
 * commit is not in the local history (a shallow clone) the check is skipped, or fails with `require`.
 */
export function checkPin(texts, fail, { git = gitRun, require = false } = {}) {
  const pins = new Set();
  for (const t of texts) for (const m of t.text.matchAll(/git checkout --detach ([0-9a-f]{40})\b/g)) pins.add(m[1]);
  if (pins.size !== 1) {
    fail(`the tutorial must check out exactly one full commit id, found ${JSON.stringify([...pins])}`);
    return null;
  }
  const [pin] = pins;
  if (!git(['cat-file', '-e', `${pin}^{commit}`]).ok) {
    if (require) fail(`pinned commit ${pin} is not in the local history (fetch the full history)`);
    return null;
  }
  if (!git(['merge-base', '--is-ancestor', pin, 'HEAD']).ok) fail(`pinned commit ${pin} is not an ancestor of HEAD`);
  if (!git(['diff', '--quiet', pin, '--', 'examples/openstack']).ok) {
    fail(`examples/openstack differs between the pinned commit ${pin} and this tree: update the pin`);
  }
  const want = git(['log', '-1', '--format=%H %s', pin]).out.trim();
  let samples = 0;
  for (const t of texts) {
    const blocks = codeBlocks(t.text);
    blocks.forEach((b, i) => {
      if (b.lang !== 'sh' || b.code.trim().split('\n').pop().trim() !== "git log -1 --format='%H %s'") return;
      samples++;
      const shown = blocks[i + 1]?.lang === 'text' ? blocks[i + 1].code.trim().split('\n')[0] : undefined;
      if (shown !== want) fail(`${t.locale}/${t.name}.mdx:${b.line}: git log sample "${shown}" != "${want}"`);
    });
  }
  if (!samples) fail('no `git log -1 --format=\'%H %s\'` sample for the pinned commit');
  return pin;
}

function realValidate(sinterBin) {
  const run = (cwd, recipe) => {
    const r = spawnSync(sinterBin, ['validate', recipe], { cwd, encoding: 'utf8' });
    return (r.stdout || '').trim() || (r.stderr || '').trim();
  };
  const tmp = mkdtempSync(join(tmpdir(), 'tutorial-check-'));
  try {
    const copy = join(tmp, 'openstack');
    cpSync(recipeDir, copy, { recursive: true });
    // synthetic secrets only: the CI sample stands in for tools/gen-secrets.sh
    cpSync(join(copy, 'secrets.example'), join(copy, 'secrets'), { recursive: true });
    return Object.fromEntries(SINTER_RECIPES.map((r) => [r, run(copy, r)]));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

// --- main ---------------------------------------------------------------------

export function loadContext() {
  const recipeFiles = new Set();
  const texts = [];
  const walk = (dir, rel) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(join(dir, e.name), r);
      else { recipeFiles.add(r); if (!r.startsWith('secrets.example/')) texts.push(readFileSync(join(dir, e.name), 'utf8')); }
    }
  };
  walk(recipeDir, '');
  return {
    recipeFiles,
    recipeText: texts.join('\n'),
    siteYaml: readFileSync(join(recipeDir, 'site.yaml'), 'utf8'),
    builderYaml: readFileSync(join(recipeDir, 'builder.yaml'), 'utf8'),
    stageOptions: scriptOptions(readFileSync(join(recipeDir, 'tools/stage-rpm-repo.sh'), 'utf8')),
    sinterOptions: sinterOptions(readFileSync(join(repo, 'src/main.rs'), 'utf8')),
  };
}

function main() {
  let failures = 0;
  const fail = (msg) => { failures++; console.error(`FAIL  ${msg}`); };
  const ctx = loadContext();
  const pages = { en: {}, ja: {} };
  const texts = [];
  let blocks = 0;
  for (const locale of LOCALES) {
    const dir = join(root, PAGES_DIR.replace('{locale}', locale));
    if (!existsSync(dir)) { fail(`${dir} does not exist`); continue; }
    for (const f of readdirSync(dir).filter((f) => f.endsWith('.mdx')).sort()) {
      const name = f.replace(/\.mdx$/, '');
      const text = readFileSync(join(dir, f), 'utf8');
      texts.push({ locale, name, text });
      pages[locale][name] = checkPage({ locale, name, text }, ctx, fail);
      blocks += pages[locale][name].length;
    }
  }
  checkParity(pages, fail, texts);
  checkRecipeFacts(texts, ctx, fail);
  const pin = checkPin(texts, fail, { require: process.env.TUTORIAL_REQUIRE_PIN === '1' });
  console.log(pin ? `ok    pinned commit ${pin}: ancestor of HEAD, same examples/openstack, git log sample` : 'skip  pinned commit not in the local history (TUTORIAL_REQUIRE_PIN=1 makes this fail)');
  if (process.env.SINTER_BIN) {
    const want = realValidate(process.env.SINTER_BIN);
    checkSamples(texts, fail, want);
    console.log(`ok    sinter validate: ${JSON.stringify(want)}`);
  } else {
    checkSamples(texts, fail);
    console.log('skip  real sinter validate counts (set SINTER_BIN to compare the samples with a build)');
  }
  if (failures) {
    console.error(`\ntutorial:check FAILED — ${failures} problem(s)`);
    process.exit(1);
  }
  console.log(`ok    ${texts.length} pages, ${blocks} shell blocks: host titles, bash -n, en/ja parity (commands, labels, numbers), recipe references, sample summaries, IPv4 literals`);
  console.log('\ntutorial:check OK');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
