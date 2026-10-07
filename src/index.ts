export interface Env {
  COVER_TOKEN_SECRET?: string;
}

const ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  "i.ytimg.com",
  "yt3.ggpht.com",
  "lh3.googleusercontent.com",
  "yt3.googleusercontent.com",
]);

const ALLOWED_SIZES = [128, 256, 512, 1024] as const;
const DEFAULT_SIZE = 512;

const CACHE_CONTROL =
  "public, max-age=604800, s-maxage=2592000, immutable";

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

function base64UrlToBytes(input: string): Uint8Array {
  const binary = base64UrlDecode(input);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

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

export function splitToken(token: string): { payload: string; signature: string | null } {
  const dot = token.indexOf(".");
  return dot === -1
    ? { payload: token, signature: null }
    : { payload: token.slice(0, dot), signature: token.slice(dot + 1) };
}

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
    return errorResponse(
      originResponse.status === 404 ? 404 : 502,
      `Cover origin responded ${originResponse.status}.`,
    );
  }

  const contentType = originResponse.headers.get("content-type") ?? "";
  if (!contentType.startsWith("image/")) {
    return errorResponse(502, "Cover origin did not return an image.");
  }

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
