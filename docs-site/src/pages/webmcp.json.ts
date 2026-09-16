import type { APIRoute } from 'astro';
import { buildWebmcp } from '../data/build-webmcp';

// Phase 1 URL kept valid: the unprefixed payload is the default (English)
// locale document. Canonical per-locale endpoints are /webmcp/<locale>.json.
export const GET: APIRoute = () => {
  return new Response(JSON.stringify(buildWebmcp('en')), {
    headers: { 'Content-Type': 'application/json' },
  });
};
