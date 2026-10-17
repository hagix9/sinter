// Tests for check-tutorial-commands.mjs: each check must reject the mistake it exists for.
// Run: node --test scripts/check-tutorial-commands.test.mjs   (from docs-site/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  codeBlocks,
  normalizeShell,
  bashSyntaxError,
  scriptOptions,
  sinterOptions,
  checkPage,
  checkCommands,
  checkParity,
  checkRecipeFacts,
  checkSamples,
  checkHostAndVars,
  checkPin,
  hasWord,
  loadContext,
} from './check-tutorial-commands.mjs';

const ctx = loadContext();
const collect = (fn) => {
  const msgs = [];
  fn((m) => msgs.push(m));
  return msgs;
};
const block = (code) => ({ code, line: 1 });

test('the real recipe context has what the tutorial relies on', () => {
  for (const o of ['--from-builder', '--host', '--identity', '--archive', '--sums']) assert.ok(ctx.stageOptions.has(o), o);
  for (const o of ['--host', '--user', '--identity', '--known-hosts', '--sudo', '--hosts']) assert.ok(ctx.sinterOptions.has(o), o);
  assert.ok(ctx.recipeFiles.has('tools/stage-rpm-repo.sh'));
});

test('code blocks keep their language, title and line', () => {
  const b = codeBlocks('x\n\n```sh title="Builder"\necho hi\n```\n\n```text\nout\n```\n');
  assert.deepEqual(b.map((x) => [x.lang, x.title, x.code, x.line]), [
    ['sh', 'Builder', 'echo hi\n', 3],
    ['text', null, 'out\n', 7],
  ]);
});

test('normalization drops comments and placeholder wording only', () => {
  assert.equal(normalizeShell('# note\nA=1  # 書き換える\necho \'<公開鍵>\'\n'), "A=1\necho '<>'");
  assert.equal(normalizeShell("echo '<public key>'"), "echo '<>'");
  assert.notEqual(normalizeShell('sinter plan x --sudo'), normalizeShell('sinter plan x'));
});

test('bash -n rejects an unquoted <placeholder>', () => {
  assert.match(bashSyntaxError('ssh <user>@<host>\n'), /syntax error/);
  assert.equal(bashSyntaxError('ssh "<user>@<host>"\n'), null);
});

test('option parsers read the shapes used by the sources', () => {
  assert.deepEqual([...scriptOptions('  --dest) D="$2";;\n  -h|--help) x;;\n  --from-builder) B=1;;\n')].sort(), ['--dest', '--from-builder']);
  const opts = sinterOptions('#[arg(long)]\n    known_hosts: Option<PathBuf>,\n#[arg(long = "identity")]\n    identity: Vec<PathBuf>,\n#[arg(long, visible_alias = "hosts")]\n    inventory: Option<PathBuf>,\n#[arg(short = \'x\')]\n    nolong: bool,\n');
  for (const o of ['--known-hosts', '--identity', '--inventory', '--hosts']) assert.ok(opts.has(o), o);
  assert.ok(!opts.has('--nolong'));
});

test('command references are checked against the recipe and the CLI', () => {
  const cases = [
    ['bash tools/stage-rpm-repo.sh --from-builder localhost --hots x', /no option --hots/],
    ['sinter apply all-in-one.yaml --host x --sudoo', /sinter has no option --sudoo/],
    ['sinter deploy all-in-one.yaml', /unexpected sinter subcommand deploy/],
    ['sinter validate allinone.yaml', /recipe file allinone\.yaml/],
    ['bash tools/missing.sh', /recipe file tools\/missing\.sh/],
    ['openstack server create --network nonet --wait vm', /network nonet/],
    ['openstack server create --flavor m9.huge vm', /flavor m9\.huge/],
    ['source /etc/sinter-openstack/admin-rc', /admin-rc does not appear/],
    ['for s in httpd not-a-unit; do systemctl is-active "$s"; done', /unit not-a-unit/],
    ['git checkout --detach c5fe8aa', /not a full commit id/],
    ['openstack server create --network hagistack-ten vm', /network hagistack-ten /],
    ['source /etc/sinter-openstack/admin-openr', /admin-openr does not appear/],
    ['sudo systemctl restart openstack-nova-computer', /unit openstack-nova-computer/],
    ['sudo journalctl -u nova-compute -n 50', /unit nova-compute /],
    ['sinter apply all-in-one.yaml --host "$AIO_IP" --user "$USER" --identity "$SSH_KEY"', /must pass --sudo/],
    ['sinter plan all-in-one.yaml --user "$USER" --identity k --sudo', /must pass --host/],
    ['sinter apply builder.yaml', /must run as `sudo env HOME=\/root/],
    ['sudo sinter apply builder.yaml', /must run as `sudo env HOME=\/root/],
  ];
  for (const [code, re] of cases) {
    const msgs = collect((fail) => checkCommands(block(code), ctx, fail));
    assert.ok(msgs.some((m) => re.test(m)), `${code} -> ${JSON.stringify(msgs)}`);
  }
  const good = 'cd ~/sinter/examples/openstack\nsinter plan all-in-one.yaml --host "$AIO_IP" --user "$USER" --identity "$SSH_KEY" --sudo\nsudo env HOME=/root /usr/local/bin/sinter apply builder.yaml\ngit clone https://github.com/hagix9/sinter.git ~/sinter\ncd ~/sinter\n';
  assert.deepEqual(collect((fail) => checkCommands(block(good), ctx, fail)), []);
});

test('whole-name matching does not accept a prefix', () => {
  assert.ok(hasWord('args: [os-net-tenant, hagistack-tenant, x]', 'hagistack-tenant'));
  assert.ok(!hasWord('args: [os-net-tenant, hagistack-tenant, x]', 'hagistack-ten'));
  assert.ok(!hasWord('path: /etc/sinter-openstack/admin-openrc', 'admin-openr'));
  assert.ok(hasWord('path: /etc/sinter-openstack/admin-openrc', 'admin-openrc'));
});

test('commands must be in sh blocks, and every block has a language', () => {
  for (const fence of ['bash', 'shell', 'console']) {
    const msgs = collect((fail) => checkPage({ locale: 'en', name: 't', text: `\`\`\`${fence} title="Builder"\nsinter validate nope.yaml\n\`\`\`\n` }, ctx, fail));
    assert.ok(msgs.some((m) => new RegExp(`use \`\`\`sh.*${fence}`).test(m)), `${fence}: ${JSON.stringify(msgs)}`);
  }
  const msgs = collect((fail) => checkPage({ locale: 'en', name: 't', text: '```\nls\n```\n' }, ctx, fail));
  assert.ok(msgs.some((m) => /without a language/.test(m)));
});

test('a shell block needs a known host title and synthetic IPs', () => {
  const text = '```sh\necho 1\n```\n\n```sh title="Somewhere"\necho 2\n```\n\n```sh title="Builder"\nssh 198.51.100.7\n```\n\nprose 203.0.113.9\n';
  const msgs = collect((fail) => checkPage({ locale: 'en', name: 't', text }, ctx, fail));
  assert.ok(msgs.some((m) => /needs a host title.*null/.test(m)));
  assert.ok(msgs.some((m) => /needs a host title.*"Somewhere"/.test(m)));
  assert.ok(msgs.some((m) => /198\.51\.100\.7 is not an allowed/.test(m)));
  assert.ok(msgs.some((m) => /203\.0\.113\.9 in prose/.test(m)));
});

test('en and ja must carry the same commands on the same hosts', () => {
  const en = { p: [{ host: 'builder', code: 'a', line: 1 }, { host: 'aio', code: 'b', line: 2 }] };
  assert.deepEqual(collect((fail) => checkParity({ en, ja: { p: [{ host: 'builder', code: 'a', line: 1 }, { host: 'aio', code: 'b', line: 9 }] } }, fail)), []);
  assert.ok(collect((fail) => checkParity({ en, ja: { p: [{ host: 'builder', code: 'a', line: 1 }, { host: 'aio', code: 'c', line: 2 }] } }, fail)).some((m) => /differs/.test(m)));
  assert.ok(collect((fail) => checkParity({ en, ja: { p: [{ host: 'builder', code: 'a', line: 1 }, { host: 'builder', code: 'b', line: 2 }] } }, fail)).some((m) => /runs on aio in en/.test(m)));
  assert.ok(collect((fail) => checkParity({ en, ja: { p: [{ host: 'builder', code: 'a', line: 1 }] } }, fail)).some((m) => /2 shell blocks, ja has 1/.test(m)));
  assert.ok(collect((fail) => checkParity({ en, ja: {} }, fail)).some((m) => /ja\/p\.mdx is missing/.test(m)));
});

test('site.yaml defaults that the sed edit replaces must stay unique', () => {
  assert.deepEqual(collect((fail) => checkRecipeFacts([], ctx, fail)), []);
  const changed = { ...ctx, siteYaml: ctx.siteYaml + '\n  provider_gateway2:\n    value: "10.0.0.10"\n' };
  assert.ok(collect((fail) => checkRecipeFacts([], changed, fail)).some((m) => /exactly mgmt_ip and controller_ip/.test(m)));
  const wrongPin = [{ locale: 'en', name: 'p', text: '8225c50c' + '0'.repeat(32) }];
  assert.ok(collect((fail) => checkRecipeFacts(wrongPin, ctx, fail)).some((m) => /hagistack commit/.test(m)));
});

const page = (locale, name, text) => ({ locale, name, text });
const validateBlock = (recipe, sample) => `\`\`\`sh title="Builder"\ncd ~/sinter/examples/openstack\nsinter validate ${recipe}\n\`\`\`\n\n\`\`\`text title="Success"\n${sample}\n\`\`\`\n`;
const okSamples = validateBlock('builder.yaml', 'ok: 20 resource(s), 0 handler(s), 3 var(s)') + validateBlock('all-in-one.yaml', 'ok: 172 resource(s), 12 handler(s), 40 var(s)');

test('every sinter validate block has its sample, and the samples match a real run', () => {
  assert.deepEqual(collect((fail) => checkSamples([page('en', 'p', okSamples)], fail)), []);
  // prose between the command and its sample does not hide the sample from the comparison
  const prose = okSamples.replace('```\n\n```text title="Success"\nok: 20', '```\n\nSome words.\n\n```text title="Success"\nok: 21');
  const real = { 'builder.yaml': 'ok: 20 resource(s), 0 handler(s), 3 var(s)', 'all-in-one.yaml': 'ok: 172 resource(s), 12 handler(s), 40 var(s)' };
  assert.ok(collect((fail) => checkSamples([page('en', 'p', prose)], fail, real)).some((m) => /sample "ok: 21 .*" != sinter validate builder\.yaml/.test(m)));
  // another block between the command and its sample is a missing sample
  const other = okSamples.replace('```\n\n```text title="Success"\nok: 20', '```\n\n```sh title="Builder"\nls\n```\n\n```text title="Success"\nok: 20');
  assert.ok(collect((fail) => checkSamples([page('en', 'p', other)], fail)).some((m) => /builder\.yaml has no "ok: …" sample/.test(m)));
  const want = { 'builder.yaml': 'ok: 21 resource(s), 0 handler(s), 3 var(s)', 'all-in-one.yaml': 'ok: 172 resource(s), 12 handler(s), 40 var(s)' };
  assert.ok(collect((fail) => checkSamples([page('en', 'p', okSamples)], fail, want)).some((m) => /sample "ok: 20 .*" != sinter validate builder\.yaml/.test(m)));
  assert.ok(collect((fail) => checkSamples([page('en', 'p', validateBlock('builder.yaml', 'ok: 20 resource(s), 0 handler(s), 3 var(s)'))], fail)).some((m) => /no sinter validate all-in-one\.yaml sample/.test(m)));
});

test('sample summaries add up and use the recipe resource count', () => {
  const summary = (line) => [page('en', 'p', okSamples), page('en', 'deploy', `\`\`\`text title="Success"\n${line}\n\`\`\`\n`)];
  assert.deepEqual(collect((fail) => checkSamples(summary('summary: 141 changed, 0 possible, 0 failed, 0 indeterminate, 172 total'), fail)), []);
  assert.deepEqual(collect((fail) => checkSamples(summary('summary: 172 total, 81 compliant, 0 drifted, 91 not_auditable, 0 not_applicable, 0 errors'), fail)), []);
  assert.ok(collect((fail) => checkSamples(summary('summary: 141 changed, 0 possible, 0 failed, 0 indeterminate, 171 total'), fail)).some((m) => /171 total != 172 resources of all-in-one\.yaml/.test(m)));
  assert.ok(collect((fail) => checkSamples(summary('summary: 172 total, 80 compliant, 0 drifted, 91 not_auditable, 0 not_applicable, 0 errors'), fail)).some((m) => /do not add up/.test(m)));
  assert.ok(collect((fail) => checkSamples(summary('summary: 172 changed, 1 possible, 0 failed, 0 indeterminate, 172 total'), fail)).some((m) => /exceed the total/.test(m)));
  assert.ok(collect((fail) => checkSamples(summary('summary: 3 things'), fail)).some((m) => /unrecognised summary/.test(m)));
});

test('evidence labels and prose numbers must agree between en and ja', () => {
  const pages = { en: { p: [] }, ja: { p: [] } };
  const en = 'Built in 41 minutes. <Badge text="Run in acceptance" variant="success" />';
  assert.deepEqual(collect((fail) => checkParity(pages, fail, [page('en', 'p', en), page('ja', 'p', '41 分でビルド。<Badge text="受入で実行" variant="success" />')])), []);
  assert.ok(collect((fail) => checkParity(pages, fail, [page('en', 'p', en), page('ja', 'p', '41 分。<Badge text="未検証" variant="danger" />')])).some((m) => /evidence labels differ/.test(m)));
  assert.ok(collect((fail) => checkParity(pages, fail, [page('en', 'p', en), page('ja', 'p', '14 分。<Badge text="受入で実行" variant="success" />')])).some((m) => /numbers in the prose differ: only en \[41\] only ja \[14\]/.test(m)));
});

test('commands run on their host and read only variables that are set', () => {
  const run = (code, host, defined = new Set()) => collect((fail) => checkHostAndVars(block(code), host, defined, fail));
  assert.ok(run('sinter apply all-in-one.yaml --host x', 'aio').some((m) => /runs on aio, but sinter runs on the builder/.test(m)));
  assert.ok(run('openstack server list', 'builder').some((m) => /OpenStack commands run as root on the AIO node/.test(m)));
  assert.ok(run('bash tools/stage-rpm-repo.sh --from-builder localhost --host "$AIO_IP"', 'builder').some((m) => /\$AIO_IP without `\. ~\/sinter-os\.env`/.test(m)));
  assert.deepEqual(run('. ~/sinter-os.env\nssh -i "$SSH_KEY" "$AIO_IP" true', 'builder'), []);
  assert.ok(run('. ~/sinter-os.env\nssh -i "$SSHKEY" "$AIO_IP" true', 'builder').some((m) => /\$SSHKEY, which no earlier block/.test(m)));
  const defined = new Set();
  assert.deepEqual(run('IP=1\nNS=$(ip netns list)', 'aio-root', defined), []);
  assert.deepEqual(run('ip netns exec "$NS" ping "$IP"', 'aio-root', defined), []);
  assert.deepEqual(run("for s in a b; do echo \"$s\"; done\nsudo sh -c 'bad=0; for f in x; do echo $f $bad; done'", 'aio'), []);
});

test('the pinned commit must exist, be an ancestor, carry the same recipes and match the log sample', () => {
  const pin = 'a'.repeat(40);
  const pageText = (id, shown) => `\`\`\`sh title="Builder"\ngit checkout --detach ${id}\ngit log -1 --format='%H %s'\n\`\`\`\n\n\`\`\`text title="Success"\n${shown}\n\`\`\`\n`;
  const fakeGit = (bad = {}) => (args) => {
    const k = args[0] === 'merge-base' ? 'ancestor' : args[0];
    if (bad[k]) return { ok: false, out: '' };
    return { ok: true, out: args[0] === 'log' ? `${pin} subject line\n` : '' };
  };
  const run = (texts, git, require = false) => collect((fail) => checkPin(texts, fail, { git, require }));
  const good = [page('en', 'prepare', pageText(pin, `${pin} subject line`))];
  assert.deepEqual(run(good, fakeGit()), []);
  assert.ok(run(good, fakeGit({ 'cat-file': true }), true).some((m) => /not in the local history/.test(m)));
  assert.deepEqual(run(good, fakeGit({ 'cat-file': true })), []);
  assert.ok(run(good, fakeGit({ ancestor: true })).some((m) => /not an ancestor of HEAD/.test(m)));
  assert.ok(run(good, fakeGit({ diff: true })).some((m) => /examples\/openstack differs/.test(m)));
  assert.ok(run([page('en', 'prepare', pageText(pin, `${pin} other subject`))], fakeGit()).some((m) => /git log sample/.test(m)));
  assert.ok(run([...good, page('ja', 'prepare', pageText('b'.repeat(40), 'x'))], fakeGit()).some((m) => /exactly one full commit id/.test(m)));
});
