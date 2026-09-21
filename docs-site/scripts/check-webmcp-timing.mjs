// WebMCP registration-timing regression check (Node, no browser required).
//
// Reproduces the four lifecycle cases that matter for Site Tools discovery:
//
//   A  modelContext exists before module evaluation     -> 5 tools now
//   B  modelContext appears between eval and DOMContentLoaded
//      (the previous permanent-miss defect)              -> 5 tools at DCL
//   C  no modelContext anywhere                         -> 0 tools, no throw
//   D  repeated registration attempts                   -> still 5 tools
//
// Each case imports public/webmcp.js with a unique query so Node's module
// cache gives every case a fresh module instance. The script only stubs the
// `document` global; the module's navigator fallback is left alone.

const mod = (tag) =>
  new URL(`../public/webmcp.js?case=${tag}`, import.meta.url).href;

let failures = 0;
const fail = (m) => { failures++; console.error(`FAIL  ${m}`); };
const ok = (m) => console.log(`ok    ${m}`);

const EXPECTED = [
  'sinter_search_docs',
  'sinter_list_resources',
  'sinter_get_resource',
  'sinter_get_compatibility',
  'sinter_get_installation',
];

function harness(readyState, withMc) {
  const tools = [];
  const listeners = {};
  globalThis.document = {
    readyState,
    addEventListener(type, fn) {
      listeners[type] = fn;
    },
    ...(withMc
      ? { modelContext: { registerTool: (t) => tools.push(t) } }
      : {}),
  };
  return { tools, listeners };
}

function assertTools(tag, tools) {
  const names = tools.map((t) => t.name).sort();
  if (names.length !== 5 || JSON.stringify(names) !== JSON.stringify(EXPECTED.slice().sort())) {
    fail(`${tag}: expected 5 tools ${EXPECTED.join(',')}, got [${names.join(', ')}]`);
    return;
  }
  if (tools.some((t) => typeof t.execute !== 'function')) {
    fail(`${tag}: a registered tool has no execute function`);
    return;
  }
  ok(`${tag}: exactly 5 tools registered`);
}

// Case A — API present before evaluation, document already complete.
{
  const h = harness('complete', true);
  await import(mod('A'));
  assertTools('A api-before-eval', h.tools);
  if (h.listeners.DOMContentLoaded) {
    fail('A: registered a DOMContentLoaded listener on a complete document');
  }
}

// Case B — API absent at eval while loading; appears before DOMContentLoaded.
{
  const h = harness('loading', false);
  await import(mod('B'));
  if (h.tools.length !== 0) {
    fail('B: tools registered during module evaluation while API absent');
  }
  if (typeof h.listeners.DOMContentLoaded !== 'function') {
    fail('B: no DOMContentLoaded registration listener installed');
  }
  // Probe fires while API still absent: must NOT mark the page registered.
  h.listeners.DOMContentLoaded?.();
  if (h.tools.length !== 0) fail('B: phantom registration with no API');
  // API appears; a second delivery of DOMContentLoaded must now register.
  globalThis.document.modelContext = { registerTool: (t) => h.tools.push(t) };
  h.listeners.DOMContentLoaded?.();
  assertTools('B api-at-DOMContentLoaded', h.tools);
}

// Case C — no API anywhere, document complete.
{
  const h = harness('complete', false);
  await import(mod('C'));
  if (h.tools.length !== 0) {
    fail('C: registered tools with no modelContext');
  } else {
    ok('C: no API -> zero tools, no exception');
  }
}

// Case D — loading document, API present at DCL; listener fired twice.
{
  const h = harness('loading', true);
  await import(mod('D'));
  h.listeners.DOMContentLoaded?.();
  h.listeners.DOMContentLoaded?.();
  if (h.tools.length !== 5) {
    fail(`D: duplicate registration (${h.tools.length} tools)`);
  } else {
    ok('D: repeated registration attempts -> still 5 tools');
  }
}

delete globalThis.document;

if (failures) {
  console.error(`\nwebmcp:timing FAILED — ${failures} case(s)`);
  process.exit(1);
}
console.log('\nwebmcp:timing OK');
