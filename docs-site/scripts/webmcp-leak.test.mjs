// Regression tests for the WebMCP payload leak rules (webmcp-leak.mjs).
// Run: node --test scripts/webmcp-leak.test.mjs
// Every fixture is synthetic; no real user, host or path is used.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { findInternalMarkers } from './webmcp-leak.mjs';

const leaks = (s) => findInternalMarkers({ description: s });

test('product vocabulary and public path examples pass', () => {
  for (const s of [
    '公開前に staging ファイルに対して実行する検証コマンド。',
    'v1.5.1 では {{ staged }} で staging ファイルのパスを引数の中に置ける。',
    'staging ファイル',
    'Validation command run against the staged file before it is published.',
    'Promote the release from staging to production.',
    'a staging/production split',
    'Staging area',
    '/srv/staging/app',
    '/opt/myapp/vimrc.local',
    '/var/lib/myapp/indexed',
    '/home/<user>/.ssh/authorized_keys',
    '/home/deploy/app/current',
    '/tmp/sinter-plan.json',
    '/etc/nginx/conf.d/site.conf',
    'https://github.com/example/sinter/releases',
    'C:\\Program Files\\Example\\app.exe',
  ]) {
    assert.deepEqual(leaks(s), [], s);
  }
});

test('the published payload sources contain no internal marker', () => {
  for (const f of ['resources.json', 'resources.ja.json', 'doc-index.json', 'doc-index.ja.json']) {
    const data = JSON.parse(readFileSync(new URL(`../src/data/${f}`, import.meta.url), 'utf8'));
    assert.deepEqual(findInternalMarkers(data), [], f);
  }
});

test('the plain markers of the earlier rule are still detected', () => {
  assert.deepEqual(leaks('/Users/example/work'), ['/Users/']);
  assert.deepEqual(leaks('sinter-CAND-x86_64'), ['CAND']);
  assert.deepEqual(leaks('check FAILED'), ['FAILED']);
  assert.deepEqual(leaks('sinter.bin'), ['.bin']);
  assert.deepEqual(leaks('SHA256SUMS.failed'), ['SHA256SUMS.failed']);
});

test('release staging and local staging paths are detected', () => {
  const cases = [
    ['~/Downloads/Sinter-v9.9.9-release-staging/SHA256SUMS', 'release-staging directory'],
    ['Sinter-v9.9.9-release_staging', 'release-staging directory'],
    ['Sinter-v9.9.9-Release-Staging', 'release-staging directory'],
    ['$HOME/staging/out', 'local staging path'],
    ['${HOME}/work/staging/out', 'local staging path'],
    ['/var/folders/xx/T/staging/out', 'local staging path'],
    ['~/staging/sinter-v9.9.9-linux-x86_64.tar.gz', 'local staging path'],
    ['/home/example-builder/work/staging/out', 'local staging path'],
    ['/tmp/staging-area/manifest.json', 'local staging path'],
    ['/private/tmp/example/Staging/notes.md', 'local staging path'],
    ['C:\\Users\\example\\staging\\notes.md', 'Windows staging path'],
  ];
  for (const [s, name] of cases) assert.ok(leaks(s).includes(name), `${s} -> ${leaks(s)}`);
});

test('local machine, build and private evidence paths are detected', () => {
  const cases = [
    ['/Volumes/EXAMPLE-SSD/projects/sinter', 'macOS volume path'],
    ['/private/var/folders/xx/T/tmp.example', 'macOS private temp path'],
    ['/var/folders/xx/T/tmp.example', 'macOS private temp path'],
    ['C:\\Users\\example\\AppData', 'Windows user path'],
    ['/home/runner/work/sinter/sinter/target', 'CI runner path'],
    ['/home/example-builder/rpmbuild/SPECS/x.spec', 'build home path'],
    ['/root/.cargo/registry/src', 'build home path'],
    ['/home/example-builder/Downloads/sinter.tar.gz', 'build home path'],
    ['.work/v9.9.9/private/harness.env', 'private evidence path'],
    ['see ./.work/v9.9.9/release-execution/public/01.txt', 'private evidence path'],
  ];
  for (const [s, name] of cases) assert.ok(leaks(s).includes(name), `${s} -> ${leaks(s)}`);
});

test('markers are found in keys, nested values and JSON escapes', () => {
  assert.deepEqual(findInternalMarkers({ '/Users/example': 1 }), ['/Users/']);
  assert.deepEqual(findInternalMarkers({ a: [{ b: ['x', 'build CAND'] }] }), ['CAND']);
  const parsed = JSON.parse('{"p":"\\u002FUsers\\u002Fexample\\u002F","q":"\\/Volumes\\/X\\/y"}');
  assert.deepEqual(findInternalMarkers(parsed), ['/Users/', 'macOS volume path']);
});

test('percent-encoded, zero-width and full-width variants are detected', () => {
  assert.ok(leaks('%2FUsers%2Fexample%2F').includes('/Users/'));
  assert.ok(leaks('%7E%2FDownloads%2FSinter-v9.9.9-release-staging%2F').includes('release-staging directory'));
  assert.ok(leaks('/Us\u200Bers/example/').includes('/Users/'));
  assert.ok(leaks('\uFF0FUsers\uFF0Fexample').includes('/Users/'));
  assert.ok(leaks('release\u2060-staging').includes('release-staging directory'));
});

test('malformed percent-encoding does not hide a raw marker or throw', () => {
  assert.deepEqual(leaks('%E0%A4%A /Users/example'), ['/Users/']);
  assert.deepEqual(leaks('100% staging ファイル'), []);
});

test('the live smoke uses these rules instead of a bare "staging" substring', () => {
  const src = readFileSync(new URL('./smoke-webmcp.mjs', import.meta.url), 'utf8');
  assert.match(src, /findInternalMarkers\(payloads\)/);
  assert.doesNotMatch(src, /'staging'/);
});
