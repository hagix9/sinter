import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import docIndex from './src/data/doc-index.json' with { type: 'json' };

// Production site is served from the GitHub Pages custom domain root.
const site = 'https://sinter.fulltrust.co.jp';
const base = '/';
const basePrefix = base === '/' ? '' : base;

// English docs live under /en/; legacy unprefixed paths redirect there.
// With a root deployment, sources and destinations are root-relative.
const legacyRedirects = Object.fromEntries(
  docIndex.pages
    .filter((p) => p.path !== '')
    .flatMap((p) => [
      [`/${p.path}/`, `${basePrefix}/en/${p.path}/`],
      [`/${p.path}`, `${basePrefix}/en/${p.path}/`],
    ]),
);
legacyRedirects['/'] = `${basePrefix}/en/`;

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
      components: {
        PageTitle: './src/components/PageTitle.astro',
      },
      head: [
        // Read-only WebMCP tool surface. The script feature-detects
        // document.modelContext / navigator.modelContext and does nothing in
        // browsers without WebMCP support.
        {
          tag: 'script',
          attrs: { type: 'module', src: `${basePrefix}/webmcp.js` },
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
            { slug: 'guides/chatgpt-plugin' },
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
            {
              label: 'Core MCP',
              translations: { ja: 'Core MCP' },
              slug: 'reference/mcp',
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
