import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import docIndex from './src/data/doc-index.json' with { type: 'json' };

// GitHub Pages project site: https://hagix9.github.io/sinter/
// If a custom domain is adopted later, change site/base together and update
// the WebMCP bootstrap path below.
const site = 'https://hagix9.github.io';
const base = '/sinter';

// Phase 1 served English docs at unprefixed paths (/sinter/<path>/). English
// now lives under /sinter/en/ so old links keep working via static redirects.
// Astro redirect sources are base-relative; destinations are absolute paths
// and must include the base explicitly.
const legacyRedirects = Object.fromEntries(
  docIndex.pages
    .filter((p) => p.path !== '')
    .flatMap((p) => [
      [`/${p.path}/`, `${base}/en/${p.path}/`],
      [`/${p.path}`, `${base}/en/${p.path}/`],
    ]),
);
legacyRedirects['/'] = `${base}/en/`;

export default defineConfig({
  site,
  base,
  redirects: legacyRedirects,
  integrations: [
    starlight({
      title: 'Sinter',
      description:
        'Sinter: agentless configuration management for Linux, built in Rust.',
      defaultLocale: 'en',
      locales: {
        en: { label: 'English', lang: 'en' },
        ja: { label: '日本語', lang: 'ja' },
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/hagix9/sinter',
        },
      ],
      customCss: ['./src/styles/custom.css'],
      head: [
        // Read-only WebMCP tool surface. The script feature-detects
        // document.modelContext / navigator.modelContext and does nothing in
        // browsers without WebMCP support.
        {
          tag: 'script',
          attrs: { type: 'module', src: `${base}/webmcp.js` },
        },
      ],
      sidebar: [
        {
          label: 'Getting Started',
          translations: { ja: 'はじめに' },
          items: [
            { slug: 'getting-started/what-is-sinter' },
            { slug: 'getting-started/installation' },
            { slug: 'getting-started/quick-start' },
            { slug: 'getting-started/first-recipe' },
          ],
        },
        {
          label: 'Concepts',
          translations: { ja: '概念' },
          items: [
            { slug: 'concepts/recipes' },
            { slug: 'concepts/resources' },
            { slug: 'concepts/idempotency' },
            { slug: 'concepts/execution-model' },
          ],
        },
        {
          label: 'Guides',
          translations: { ja: 'ガイド' },
          items: [
            { slug: 'guides/ubuntu' },
            { slug: 'guides/rocky-linux' },
            { slug: 'guides/rhel' },
            { slug: 'guides/almalinux' },
          ],
        },
        {
          label: 'Recipes',
          translations: { ja: 'レシピ' },
          items: [{ slug: 'recipes/overview' }],
        },
        {
          label: 'Reference',
          translations: { ja: 'リファレンス' },
          items: [
            { slug: 'reference/cli' },
            { slug: 'reference/recipe-format' },
            {
              label: 'Resource Reference',
              translations: { ja: 'リソースリファレンス' },
              collapsed: false,
              items: [
                { slug: 'reference/resources' },
                { slug: 'reference/resources/file' },
                { slug: 'reference/resources/directory' },
                { slug: 'reference/resources/link' },
                { slug: 'reference/resources/template' },
                { slug: 'reference/resources/command' },
                { slug: 'reference/resources/package' },
                { slug: 'reference/resources/service' },
              ],
            },
            {
              label: 'Documentation WebMCP',
              translations: { ja: 'ドキュメント WebMCP' },
              slug: 'reference/webmcp',
            },
          ],
        },
        {
          label: 'Compatibility',
          translations: { ja: '対応プラットフォーム' },
          items: [{ slug: 'compatibility/platforms' }],
        },
        {
          slug: 'troubleshooting',
          translations: { ja: 'トラブルシューティング' },
        },
        {
          slug: 'contributing',
          translations: { ja: 'コントリビューション' },
        },
      ],
    }),
  ],
});
