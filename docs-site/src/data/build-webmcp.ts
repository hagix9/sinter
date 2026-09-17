import resources from './resources.json';
import resourcesJa from './resources.ja.json';
import docIndex from './doc-index.json';
import docIndexJa from './doc-index.ja.json';

export const LOCALES = ['en', 'ja'] as const;
export type Locale = (typeof LOCALES)[number];

// Language-independent facts (compatibility matrix, release artifacts) live
// once in this file / resources.json. Per-locale data files carry prose only:
// resources.<locale>.json overrides summary + parameter descriptions keyed by
// the same resource type / parameter names, so a new parameter only needs its
// facts added in resources.json — untranslated prose falls back to English.
interface ParamOverlay {
  summary?: string;
  parameters?: Record<string, string>;
}

const overlay: Record<Locale, Record<string, ParamOverlay>> = {
  en: {},
  ja: resourcesJa.resourceTypes,
};

const indexes: Record<Locale, typeof docIndex.pages> = {
  en: docIndex.pages,
  ja: docIndexJa.pages,
};

const requirementsI18n: Record<Locale, string[]> = {
  en: [
    'systemd',
    'OpenSSH server',
    '/bin/sh',
    'passwordless sudo -n when privilege escalation is required',
  ],
  ja: [
    'systemd',
    'OpenSSH サーバ',
    '/bin/sh',
    '権限昇格が必要な場合はパスワードなしの sudo -n',
  ],
};

export function buildWebmcp(locale: Locale) {
  const l10n = overlay[locale] ?? {};
  const resourceTypes = resources.resourceTypes.map((r) => {
    const ov = l10n[r.type];
    return {
      ...r,
      summary: ov?.summary ?? r.summary,
      docPath: `${locale}/${r.docPath}`,
      parameters: r.parameters.map((p) => ({
        ...p,
        description: ov?.parameters?.[p.name] ?? p.description,
      })),
    };
  });
  return {
    version: resources.version,
    locale,
    defaultLocale: 'en',
    pages: indexes[locale].map((p) => ({
      ...p,
      path: p.path === '' ? locale : `${locale}/${p.path}`,
    })),
    resourceTypes,
    compatibility: {
      platforms: [
        {
          name: 'Ubuntu 24.04 LTS',
          arch: 'amd64',
          packageBackend: 'apt',
          status: 'supported',
        },
        {
          name: 'Rocky Linux 9',
          arch: 'x86_64',
          packageBackend: 'dnf',
          status: 'supported',
          acceptanceReference: 'Rocky Linux 9.8 x86_64, DNF 4.14.0',
        },
      ],
      requirements: requirementsI18n[locale],
    },
    installation: {
      release: 'v0.2.1',
      artifacts: [
        'sinter-v0.2.1-ubuntu24.04-amd64.tar.gz',
        'sinter-v0.2.1-rocky9-x86_64.tar.gz',
        'SHA256SUMS',
      ],
      releaseUrl: 'https://github.com/hagix9/sinter/releases',
    },
  };
}
