// Sinter documentation — read-only WebMCP tool surface.
//
// WebMCP is an early W3C Community Group draft. The API object has existed
// under both `navigator.modelContext` and `document.modelContext`; this
// script feature-detects both and registers nothing when neither exists.
// All tools are documentation lookups only — no mutation, no execution.
//
// Locale policy (documented for agents):
//   - Every tool accepts an optional `locale` input: "en" or "ja".
//   - When omitted, the locale is detected from the current page URL
//     (<base>/ja/... → "ja", anything else → "en").
//   - An invalid locale value fails cleanly with an error listing the
//     supported locales.
//   - If a localized payload cannot be fetched, the tool falls back to the
//     English document rather than failing.

// Registration timing: module scripts execute before DOMContentLoaded, and
// a WebMCP host may expose modelContext only once the document is ready. A
// one-shot probe at evaluation time can therefore permanently miss the API.
// Defer the first registration attempt to DOMContentLoaded when the document
// is still loading; otherwise register immediately. `registered` is set only
// after a usable modelContext is found, never by a probe that found none.
var registered = false;

function register() {
  'use strict';

  if (registered) {
    return;
  }
  var mc =
    (typeof document !== 'undefined' && document.modelContext) ||
    (typeof navigator !== 'undefined' && navigator.modelContext);
  if (!mc || typeof mc.registerTool !== 'function') {
    return; // WebMCP unsupported — normal documentation still works.
  }
  registered = true;

  var LOCALES = ['en', 'ja'];
  var scriptUrl = new URL(import.meta.url);
  var base = scriptUrl.pathname.replace(/webmcp\.js$/, ''); // e.g. /

  var dataPromises = {};
  function data(locale) {
    if (!dataPromises[locale]) {
      dataPromises[locale] = fetch(base + 'webmcp/' + locale + '.json').then(
        function (r) {
          if (!r.ok) throw new Error('webmcp ' + locale + ' unavailable');
          return r.json();
        }
      );
      if (locale !== 'en') {
        // Fallback policy: a missing localized payload degrades to English.
        dataPromises[locale] = dataPromises[locale].catch(function () {
          return data('en');
        });
      }
    }
    return dataPromises[locale];
  }

  function text(value) {
    return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
  }

  function pageUrl(path) {
    return new URL(base + path + '/', scriptUrl.origin).href;
  }

  // Returns { locale } on success or { error } for a clean failure.
  function resolveLocale(input) {
    var locale = input && input.locale;
    if (locale == null) {
      var m =
        typeof location !== 'undefined' &&
        location.pathname.indexOf(base + 'ja/') === 0;
      return { locale: m ? 'ja' : 'en' };
    }
    if (LOCALES.indexOf(locale) === -1) {
      return {
        error: text({
          error: 'unsupported locale: ' + locale,
          supportedLocales: LOCALES,
        }),
      };
    }
    return { locale: locale };
  }

  var localeProp = {
    type: 'string',
    description:
      'Documentation locale: en or ja. Defaults to the locale of the page the agent is currently viewing.',
    enum: LOCALES,
  };

  var installSteps = {
    en: function (artifact, releaseUrl) {
      return [
        'Download ' + artifact + ' and SHA256SUMS from ' + releaseUrl,
        'Verify: sha256sum -c SHA256SUMS',
        'Extract: tar -xzf ' + artifact,
        'Run: ./' + artifact.replace('.tar.gz', '') + '/sinter --version',
      ];
    },
    ja: function (artifact, releaseUrl) {
      return [
        releaseUrl + ' から ' + artifact + ' と SHA256SUMS をダウンロード',
        '検証: sha256sum -c SHA256SUMS',
        '展開: tar -xzf ' + artifact,
        '実行: ./' + artifact.replace('.tar.gz', '') + '/sinter --version',
      ];
    },
  };

  var sourceSteps = {
    en: [
      'Install a Rust toolchain (rustup or distribution packages).',
      'Clone https://github.com/hagix9/sinter',
      'Run: cargo build --release',
      'Binary: target/release/sinter',
    ],
    ja: [
      'Rust ツールチェーンをインストール（rustup またはディストリビューションのパッケージ）。',
      'git clone https://github.com/hagix9/sinter',
      '実行: cargo build --release',
      'バイナリ: target/release/sinter',
    ],
  };

  mc.registerTool({
    name: 'sinter_search_docs',
    description:
      'Search the Sinter documentation index. Returns matching documentation pages with title, URL, and summary. Sinter is an agentless configuration-management tool for Linux.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description:
            'Free-text query, e.g. "install", "rocky", "インストール".',
        },
        locale: localeProp,
      },
      required: ['query'],
    },
    execute: function (input) {
      var loc = resolveLocale(input);
      if (loc.error) return Promise.resolve(loc.error);
      var q = String((input && input.query) || '')
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean);
      return data(loc.locale).then(function (d) {
        var hits = d.pages
          .map(function (p) {
            var hay = (
              p.title +
              ' ' +
              p.description +
              ' ' +
              (p.keywords || '')
            ).toLowerCase();
            var score = q.reduce(function (s, w) {
              return s + (hay.indexOf(w) !== -1 ? 1 : 0);
            }, 0);
            return { p: p, score: score };
          })
          .filter(function (h) {
            return h.score > 0;
          })
          .sort(function (a, b) {
            return b.score - a.score;
          })
          .slice(0, 8)
          .map(function (h) {
            return {
              title: h.p.title,
              url: pageUrl(h.p.path),
              summary: h.p.description,
            };
          });
        return text({
          query: (input && input.query) || '',
          locale: d.locale,
          results: hits,
        });
      });
    },
  });

  mc.registerTool({
    name: 'sinter_list_resources',
    description:
      'List all Sinter recipe resource types implemented in the current release, with a one-line summary and documentation URL for each.',
    inputSchema: {
      type: 'object',
      properties: { locale: localeProp },
    },
    execute: function (input) {
      var loc = resolveLocale(input);
      if (loc.error) return Promise.resolve(loc.error);
      return data(loc.locale).then(function (d) {
        return text({
          version: d.version,
          locale: d.locale,
          resources: d.resourceTypes.map(function (r) {
            return {
              type: r.type,
              summary: r.summary,
              url: pageUrl(r.docPath),
            };
          }),
        });
      });
    },
  });

  mc.registerTool({
    name: 'sinter_get_resource',
    description:
      'Get the full parameter reference for one Sinter resource type: required/optional parameters, types, defaults, accepted values, and a usage example.',
    inputSchema: {
      type: 'object',
      properties: {
        type: {
          type: 'string',
          description: 'Resource type name.',
          enum: [
            'file',
            'directory',
            'link',
            'template',
            'command',
            'package',
            'service',
          ],
        },
        locale: localeProp,
      },
      required: ['type'],
    },
    execute: function (input) {
      var loc = resolveLocale(input);
      if (loc.error) return Promise.resolve(loc.error);
      return data(loc.locale).then(function (d) {
        var type = input && input.type;
        var r = d.resourceTypes.find(function (x) {
          return x.type === type;
        });
        if (!r) {
          return text({ error: 'unknown resource type: ' + type });
        }
        return text({
          type: r.type,
          locale: d.locale,
          summary: r.summary,
          parameters: r.parameters,
          platforms: r.platforms,
          example: r.example,
          url: pageUrl(r.docPath),
        });
      });
    },
  });

  mc.registerTool({
    name: 'sinter_get_compatibility',
    description:
      'Get the Sinter supported-platform matrix: distributions, architectures, package backends, acceptance reference, and managed-target requirements.',
    inputSchema: {
      type: 'object',
      properties: { locale: localeProp },
    },
    execute: function (input) {
      var loc = resolveLocale(input);
      if (loc.error) return Promise.resolve(loc.error);
      return data(loc.locale).then(function (d) {
        return text({
          version: d.version,
          locale: d.locale,
          platforms: d.compatibility.platforms,
          requirements: d.compatibility.requirements,
          url: pageUrl(loc.locale + '/compatibility/platforms'),
        });
      });
    },
  });

  mc.registerTool({
    name: 'sinter_get_installation',
    description:
      'Get installation instructions for Sinter: the release tarball for a supported platform, checksum verification, or building from source.',
    inputSchema: {
      type: 'object',
      properties: {
        platform: {
          type: 'string',
          description:
            'Target platform identifier: linux-x86_64 or source (legacy Ubuntu/Rocky identifiers remain aliases).',
          enum: ['linux-x86_64', 'ubuntu24.04-amd64', 'rocky9-x86_64', 'source'],
        },
        locale: localeProp,
      },
      required: ['platform'],
    },
    execute: function (input) {
      var loc = resolveLocale(input);
      if (loc.error) return Promise.resolve(loc.error);
      var valid = ['linux-x86_64', 'ubuntu24.04-amd64', 'rocky9-x86_64', 'source'];
      if (!input || valid.indexOf(input.platform) === -1) {
        return Promise.resolve(
          text({
            error: 'invalid platform: ' + (input && input.platform),
            validPlatforms: valid,
          })
        );
      }
      return data(loc.locale).then(function (d) {
        var artifact =
          'sinter-v' +
          d.installation.release.replace(/^v/, '') +
          '-' +
          (input.platform === 'source' ? 'source' : 'linux-x86_64') +
          '.tar.gz';
        var steps =
          input.platform === 'source'
            ? sourceSteps[d.locale] || sourceSteps.en
            : (installSteps[d.locale] || installSteps.en)(
                artifact,
                d.installation.releaseUrl
              );
        return text({
          platform: input.platform,
          locale: d.locale,
          steps: steps,
          url: pageUrl(loc.locale + '/getting-started/installation'),
        });
      });
    },
  });
}

if (typeof document !== 'undefined' && document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', register, { once: true });
} else {
  register();
}
