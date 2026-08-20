/**
 * covers.tryliner.fun — cover-art proxy Worker.
 *
 * Google's image CDNs (googleusercontent / ggpht / ytimg) are unreachable for
 * many users in Russia because of RKN blocking, yet that is exactly where
 * Innertube cover art is hosted. This Worker is the client's fallback: when a
 * cover URL fails to load directly, the client swaps in
 * `https://covers.tryliner.fun/c/<token>?size=512`, which resolves to
 * Cloudflare's (unblocked) edge and — on a cache miss — re-fetches the original
 * Google image server-side and streams it back with a long TTL.
 *
 * Request shape:
 *   GET /c/<token>?size=<128|256|512|1024>
 *
 *   <token> is base64url(JSON) describing the upstream cover:
 *     { "u": "https://lh3.googleusercontent.com/…", "s": 512 }
 *   `u` is the size-agnostic origin URL (options such as `=w544` are stripped
 *   and re-applied by this Worker, so one cover is one token regardless of the
 *   size the caller happened to capture). `s` is an optional default size used
 *   when the `?size=` query param is absent.
 *
 * Security model:
 *   - The upstream host MUST be on ALLOWED_HOSTS, so this can never be turned
 *     into a general-purpose open proxy / SSRF vector.
 *   - Only https origins are fetched.
 *   - Only the four documented sizes are honored; anything else snaps to the
 *     nearest allowed size, so the edge cache can only ever hold
 *     (distinct covers × 4) entries instead of one per pixel width.
 *   - Optional HMAC: when COVER_TOKEN_SECRET is set, the token must be
 *     `<payload>.<sig>` where sig = base64url(HMAC_SHA256(secret, payload)).
 *     That stops third parties from minting tokens for arbitrary allowlisted
 *     URLs. With the secret unset the check is skipped, so the current unsigned
 *     client keeps working until the minting side (API) starts signing — see
 *     verifyToken.
 */

export interface Env {
  // HMAC secret for signed tokens. When set, tokens must carry a valid
  // `.<sig>` suffix (see verifyToken); when unset, signature checks are skipped
  // so unsigned tokens still resolve. Set with `wrangler secret put`.
  COVER_TOKEN_SECRET?: string;
}

/** Upstream image hosts this Worker is willing to fetch from. */
const ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  "i.ytimg.com",
  "yt3.ggpht.com",
  "lh3.googleusercontent.com",
  "yt3.googleusercontent.com",
]);

/** The only cover sizes that produce a distinct cache key. */
const ALLOWED_SIZES = [128, 256, 512, 1024] as const;
const DEFAULT_SIZE = 512;

// One week for shared/browser caches, one month at the CF edge. `immutable`
// tells browsers never to revalidate: a given token+size always maps to the
// same bytes, so a revalidation round-trip would be pure waste.
const CACHE_CONTROL =
  "public, max-age=604800, s-maxage=2592000, immutable";

// Upstream sub-request TTL. Lets Cloudflare cache the Google→Worker hop too,
// so even a Worker cold path after an edge purge usually avoids re-hitting
// Google (which matters when Google is the rate-limited / blocked leg).
const UPSTREAM_CACHE_TTL_SECONDS = 2_592_000;

interface DecodedToken {
  url: string;
  size?: number;
}

function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, HEAD, OPTIONS",
    "access-control-max-age": "86400",
  };
}

function errorResponse(status: number, message: string): Response {
  return new Response(message, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      // Never let a transient failure (429/5xx) get pinned at the edge.
      "cache-control": "no-store",
      ...corsHeaders(),
    },
  });
}

function base64UrlDecode(input: string): string {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const withPad = padded + "=".repeat((4 - (padded.length % 4)) % 4);
  return atob(withPad);
}

const TEXT_ENCODER = new TextEncoder();

/** base64url → raw bytes. Throws (via atob) on an invalid alphabet. */
function base64UrlToBytes(input: string): Uint8Array {
  const binary = base64UrlDecode(input);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Decode a token's payload (`base64url(JSON)`). Returns null for anything
 * malformed so the caller can answer 400 without throwing. The signature
 * suffix, if any, is stripped by the caller before this runs.
 */
export function decodeToken(payload: string): DecodedToken | null {
  let json: string;
  try {
    json = base64UrlDecode(payload);
  } catch {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null) return null;
  const record = parsed as Record<string, unknown>;
  const url = record.u ?? record.url;
  if (typeof url !== "string" || url.length === 0) return null;

  const rawSize = record.s ?? record.size;
  const size = typeof rawSize === "number" ? rawSize : undefined;
  return { url, size };
}

/** Split `<payload>.<sig>` into its parts; `signature` is null when unsigned. */
export function splitToken(token: string): { payload: string; signature: string | null } {
  const dot = token.indexOf(".");
  return dot === -1
    ? { payload: token, signature: null }
    : { payload: token.slice(0, dot), signature: token.slice(dot + 1) };
}

/**
 * Verify a token's HMAC signature.
 *
 * When `COVER_TOKEN_SECRET` is unset, signing is disabled and every token is
 * accepted (keeps the current unsigned client working). When it is set, the
 * token MUST be `<payload>.<sig>` where
 *   sig = base64url(HMAC_SHA256(secret, payload))
 * computed over the base64url *payload* string. `crypto.subtle.verify` does the
 * comparison in constant time, so this is not timing-attackable.
 */
export async function verifyToken(token: string, env: Env): Promise<boolean> {
  const secret = env.COVER_TOKEN_SECRET;
  if (!secret) return true;

  const { payload, signature } = splitToken(token);
  if (!signature) return false;

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlToBytes(signature);
  } catch {
    return false;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    TEXT_ENCODER.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );

  try {
    return await crypto.subtle.verify(
      "HMAC",
      key,
      signatureBytes,
      TEXT_ENCODER.encode(payload),
    );
  } catch {
    return false;
  }
}

/** Snap an arbitrary requested size to the nearest allowed size. */
function snapSize(requested: number | undefined): number {
  if (!requested || !Number.isFinite(requested)) return DEFAULT_SIZE;
  let best: number = ALLOWED_SIZES[0];
  let bestDelta = Math.abs(requested - best);
  for (const candidate of ALLOWED_SIZES) {
    const delta = Math.abs(requested - candidate);
    if (delta < bestDelta) {
      best = candidate;
      bestDelta = delta;
    }
  }
  return best;
}

/**
 * Rewrite a Google image URL to request exactly `size`.
 *
 * googleusercontent / ggpht encode size in a trailing options segment
 * (`=w512-h512-…` or `=s512-…`); we normalize it to a square crop, matching the
 * backend's `toSquareArtworkUrl`. i.ytimg.com has no such parameter (size lives
 * in the path filename, e.g. `hqdefault.jpg`), so it passes through unchanged.
 */
function applySize(rawUrl: string, host: string, size: number): string {
  if (host === "i.ytimg.com") return rawUrl;

  const options = `=w${size}-h${size}-l90-rj`;
  const eq = rawUrl.indexOf("=");
  const base = eq === -1 ? rawUrl : rawUrl.slice(0, eq);
  return base + options;
}

async function handleRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    return errorResponse(405, "Method not allowed.");
  }

  const url = new URL(request.url);
  const match = /^\/c\/([^/]+)\/?$/.exec(url.pathname);
  if (!match) return errorResponse(404, "Not found.");

  const token = match[1];
  // Verify over the full token, then decode only the payload half. Order
  // matters: reject a forged/altered token before parsing its contents.
  if (!(await verifyToken(token, env))) return errorResponse(403, "Invalid token.");

  const { payload } = splitToken(token);
  const decoded = decodeToken(payload);
  if (!decoded) return errorResponse(400, "Malformed token.");

  let upstream: URL;
  try {
    upstream = new URL(decoded.url);
  } catch {
    return errorResponse(400, "Malformed cover URL.");
  }

  if (upstream.protocol !== "https:") {
    return errorResponse(400, "Only https cover URLs are supported.");
  }
  if (!ALLOWED_HOSTS.has(upstream.hostname)) {
    return errorResponse(403, "Cover host is not allowed.");
  }

  const requestedSize = url.searchParams.has("size")
    ? Number(url.searchParams.get("size"))
    : decoded.size;
  const size = snapSize(requestedSize);

  // Normalized cache key: same token + snapped size always collapses to one
  // entry, regardless of the caller's original `?size=` or URL casing.
  const cacheKey = new Request(
    `${url.origin}/c/${token}?size=${size}`,
    { method: "GET" },
  );
  const cache = caches.default;

  const cached = await cache.match(cacheKey);
  if (cached) {
    return request.method === "HEAD"
      ? new Response(null, { status: cached.status, headers: cached.headers })
      : cached;
  }

  const targetUrl = applySize(upstream.toString(), upstream.hostname, size);

  let originResponse: Response;
  try {
    originResponse = await fetch(targetUrl, {
      headers: {
        accept: "image/avif,image/webp,image/*,*/*;q=0.8",
        // A UA is required or some Google endpoints answer 400/403.
        "user-agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      },
      cf: {
        cacheEverything: true,
        cacheTtl: UPSTREAM_CACHE_TTL_SECONDS,
      },
    });
  } catch {
    return errorResponse(502, "Failed to reach cover origin.");
  }

  if (!originResponse.ok) {
    // Surface the upstream status (404/429/5xx) without caching, so the client
    // can fall back and a later request can succeed once the origin recovers.
    return errorResponse(
      originResponse.status === 404 ? 404 : 502,
      `Cover origin responded ${originResponse.status}.`,
    );
  }

  const contentType = originResponse.headers.get("content-type") ?? "";
  if (!contentType.startsWith("image/")) {
    return errorResponse(502, "Cover origin did not return an image.");
  }

  // Build a fresh response so no upstream Set-Cookie / Vary / auth headers leak
  // through, and so the cache stores exactly the headers we intend.
  const headers = new Headers({
    "content-type": contentType,
    "cache-control": CACHE_CONTROL,
    "cross-origin-resource-policy": "cross-origin",
    "x-content-type-options": "nosniff",
    ...corsHeaders(),
  });
  const contentLength = originResponse.headers.get("content-length");
  if (contentLength) headers.set("content-length", contentLength);

  const body = await originResponse.arrayBuffer();
  const response = new Response(body, { status: 200, headers });

  ctx.waitUntil(cache.put(cacheKey, response.clone()));

  return request.method === "HEAD"
    ? new Response(null, { status: 200, headers })
    : response;
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
