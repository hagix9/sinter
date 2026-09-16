import type { APIRoute } from 'astro';
import { buildWebmcp, LOCALES, type Locale } from '../../data/build-webmcp';

// Per-locale machine-readable payload consumed by the in-browser WebMCP tools
// (public/webmcp.js). Derived entirely from src/data/ so documentation and
// tools never drift apart.
export function getStaticPaths() {
  return LOCALES.map((locale) => ({ params: { locale } }));
}

export const GET: APIRoute = ({ params }) => {
  return new Response(JSON.stringify(buildWebmcp(params.locale as Locale)), {
    headers: { 'Content-Type': 'application/json' },
  });
};
