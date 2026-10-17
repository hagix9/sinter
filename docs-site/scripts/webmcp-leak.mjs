// Internal-information leak detection for the public WebMCP payloads.
//
// Used by smoke-webmcp.mjs on the live payloads and by webmcp-leak.test.mjs.
// Every string (object keys included) is checked as written, after removing
// zero-width characters and NFKC normalization, and after percent-decoding.
//
// Plain markers are matched anywhere. The word "staging" alone is product
// vocabulary (validate runs against the staged file), so it only counts as a
// leak when it names a directory: the release-staging directory, or a path
// component under a local home/temporary/volume location.

const PLAIN_MARKERS = ['/Users/', 'CAND', 'FAILED', '.bin', 'SHA256SUMS.failed'];

const PATH_RULES = [
  // release staging directory (RELEASE.md: Sinter-v<version>-release-staging)
  ['release-staging directory', /release[-_]staging/i],
  // a "staging" path component below a home, temporary or mounted-volume root
  [
    'local staging path',
    /(?:~|\$HOME|\$\{HOME\}|\/Users\/[^/\s]+|\/home\/[^/\s]+|\/root|\/tmp|\/var\/tmp|\/var\/folders|\/private\/(?:tmp|var)|\/Volumes\/[^/\s]+)(?:\/[^/\s]+)*?\/[^/\s]*staging/i,
  ],
  ['Windows staging path', /\\[^\\\s]*staging[^\\\s]*\\/i],
  // local machine paths
  ['macOS volume path', /\/Volumes\//],
  ['macOS private temp path', /\/private\/(?:tmp|var)\/|\/var\/folders\//],
  ['Windows user path', /[A-Za-z]:\\Users\\/],
  // CI runner and build homes
  ['CI runner path', /\/home\/runner\/work\//],
  ['build home path', /(?:\/home\/[^/\s]+|\/root)\/(?:rpmbuild|\.cargo|\.rustup|actions-runner|Downloads)\//],
  // private evidence tree of the repository
  ['private evidence path', /(?:^|[\s"'`(=:/])\.work\//],
];

const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/g;

function* strings(value) {
  if (typeof value === 'string') yield value;
  else if (Array.isArray(value)) for (const v of value) yield* strings(v);
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      yield k;
      yield* strings(v);
    }
  }
}

function variants(s) {
  const out = [s];
  const norm = s.normalize('NFKC').replace(ZERO_WIDTH, '');
  if (norm !== s) out.push(norm);
  if (norm.includes('%')) {
    try {
      const dec = decodeURIComponent(norm);
      if (dec !== norm) out.push(dec);
    } catch {
      // not valid percent-encoding: the raw forms above are still checked
    }
  }
  return out;
}

/** Returns the sorted names of the internal markers found in `payloads`. */
export function findInternalMarkers(payloads) {
  const found = new Set();
  for (const s of strings(payloads)) {
    for (const v of variants(s)) {
      for (const m of PLAIN_MARKERS) if (v.includes(m)) found.add(m);
      for (const [name, re] of PATH_RULES) if (re.test(v)) found.add(name);
    }
  }
  return [...found].sort();
}
