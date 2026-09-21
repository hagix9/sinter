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
    'attr (/usr/bin/getfattr)',
    'passwordless sudo -n when privilege escalation is required',
  ],
  ja: [
    'systemd',
    'OpenSSH サーバ',
    '/bin/sh',
    'attr (/usr/bin/getfattr)',
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
          status: 'supported, acceptance-tested',
          acceptanceReference: 'Ubuntu 24.04.5 LTS amd64',
        },
        {
          name: 'Ubuntu 26.04 LTS',
          arch: 'amd64',
          packageBackend: 'apt',
          status: 'supported, acceptance-tested',
          acceptanceReference: 'Ubuntu 26.04.1 LTS amd64',
        },
        {
          name: 'Rocky Linux 9',
          arch: 'x86_64',
          packageBackend: 'dnf',
          status: 'supported, acceptance-tested',
          acceptanceReference: 'Rocky Linux 9.8 x86_64, DNF 4.14.0',
        },
        {
          name: 'Rocky Linux 10',
          arch: 'x86_64',
          packageBackend: 'dnf',
          status: 'supported, acceptance-tested',
          acceptanceReference: 'Rocky Linux 10.2 x86_64, DNF 4.20.0',
        },
        {
          name: 'RHEL 9',
          arch: 'x86_64',
          packageBackend: 'dnf',
          status: 'supported, acceptance-tested',
          acceptanceReference: 'RHEL 9.8 x86_64',
        },
        {
          name: 'RHEL 10',
          arch: 'x86_64',
          packageBackend: 'dnf',
          status: 'supported, acceptance-tested',
          acceptanceReference: 'RHEL 10.2 x86_64',
        },
        {
          name: 'AlmaLinux 9',
          arch: 'x86_64',
          packageBackend: 'dnf',
          status: 'supported, acceptance-tested',
          acceptanceReference: 'AlmaLinux 9.8 x86_64',
        },
        {
          name: 'AlmaLinux 10',
          arch: 'x86_64',
          packageBackend: 'dnf',
          status: 'supported, acceptance-tested',
          acceptanceReference: 'AlmaLinux 10.2 x86_64',
        },
        {
          name: 'Oracle Linux',
          arch: 'x86_64',
          packageBackend: 'dnf',
          status: 'expected compatible — not acceptance-tested',
        },
      ],
      requirements: requirementsI18n[locale],
    },
    installation: {
      release: 'v0.5.0',
      artifacts: [
        'sinter-v0.5.0-linux-x86_64.tar.gz',
        'SHA256SUMS',
      ],
      releaseUrl: 'https://github.com/hagix9/sinter/releases',
    },
  };
}
