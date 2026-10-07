# @liner/covers-worker

Cloudflare Worker behind **`covers.tryliner.fun`**. It proxies Innertube /
Google cover art so users in regions where Google's image CDNs are blocked
(RKN in Russia) can still load artwork. Cloudflare's edge is reachable there;
Google is not.

## Request flow

```
Client gets track/album/search
        ↓
API returns { coverUrl, coverFallbackUrl }
        ↓
Client tries coverUrl (direct Google) first
        ↓
works → done
fails → swap to coverFallbackUrl (this Worker)
        ↓
Cloudflare edge cache
        ├─ HIT  → image returned, Worker may not even run
        └─ MISS → Worker runs
                    ↓
             validate token + host allowlist
                    ↓
             fetch original Google URL at normalized size
                    ↓
             return image, long TTL → Cloudflare caches it
```

## Endpoint

```
GET /c/<token>?size=<128|256|512|1024>
```

- **`<token>`** — `base64url(JSON)`:
  ```json
  { "u": "https://lh3.googleusercontent.com/…", "s": 512 }
  ```
  - `u` — the size-agnostic origin URL. Any trailing `=w…-h…` / `=s…` options
    are stripped and reapplied by the Worker, so **one cover = one token**
    regardless of the size the caller captured.
  - `s` — optional default size, used when `?size=` is absent.
  - `url` / `size` long keys are also accepted.
- **`?size=`** — optional; overrides `s`. Snapped to the nearest allowed size.

### Host allowlist (hard requirement — prevents open-proxy/SSRF)

```
i.ytimg.com
yt3.ggpht.com
lh3.googleusercontent.com
yt3.googleusercontent.com
```

Only `https` origins on this list are fetched. Everything else → `403`.

### Size normalization

Only `128 / 256 / 512 / 1024` produce a distinct cache key; any other value
snaps to the nearest. This caps the edge cache at `covers × 4` entries instead
of one per pixel width (`w120`, `w240`, `w544`, … would otherwise each be a
separate key). For googleusercontent/ggpht the size is rewritten into the
URL's options segment (`=w512-h512-l90-rj`, a square crop matching the
backend's `toSquareArtworkUrl`); `i.ytimg.com` has no such param and passes
through.

### Caching

Success responses:

```
Cache-Control: public, max-age=604800, s-maxage=2592000, immutable
```

Upstream Google fetch uses `cf.cacheEverything` + 30-day `cacheTtl` so even a
Worker cold path usually avoids re-hitting Google. Errors (`404/429/5xx`) are
returned `no-store` so a transient failure never gets pinned at the edge.

## Security

- Host allowlist + `https`-only + size clamp are enforced always.
- **HMAC signing (optional, toggled by the secret being set).** When
  `COVER_TOKEN_SECRET` is configured, the token must be `<payload>.<sig>` where

  ```
  payload = base64url(JSON({ u, s }))
  sig     = base64url(HMAC_SHA256(secret, payload))
  ```

  `verifyToken()` in `src/index.ts` recomputes the signature with WebCrypto
  (`crypto.subtle.verify`, constant-time) and rejects a missing/mismatched
  signature with `403`. This stops third parties from minting tokens for
  arbitrary allowlisted URLs.
- **When the secret is unset, signing is skipped** and any decodable token is
  accepted. That is deliberate: the API/client don't sign yet, so the Worker
  stays backward-compatible until they do. The allowlist still blocks arbitrary
  destinations in that mode. Flip signing on by setting the secret on both ends;
  no code change needed.

### Secret — one value, three places

`COVER_TOKEN_SECRET` lives in the repo-root `.env` as the source of truth
(generate with `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`).
Cloudflare Workers don't read that file, so it is mirrored:

| Where | How | Used by |
|-------|-----|---------|
| repo-root `.env` | plain `KEY=value` | source of truth; the API will read it when it starts signing |
| `apps/workers/covers/.dev.vars` | plain `KEY=value` (gitignored) | `wrangler dev` (local) |
| Cloudflare | `wrangler secret put COVER_TOKEN_SECRET` | deployed Worker |

## Deploy

Wrangler resolves `wrangler.toml` from the current directory, so run its
commands from the worker folder.

```powershell
npm install                                  # from repo root; installs wrangler locally
cd apps/workers/covers
npx wrangler login                           # opens a browser; authorizes your CF account

# Push the HMAC secret. Pipe it straight from repo-root .env so that file stays
# the single source of truth (wrangler reads the value from stdin):
$secret = ((Get-Content ../../../.env | Select-String '^COVER_TOKEN_SECRET=').Line -split '=',2)[1]
$secret | npx wrangler secret put COVER_TOKEN_SECRET

# Deploy the Worker + custom domain:
npx wrangler deploy
```

On bash/zsh the secret + deploy steps are:

```bash
cd apps/workers/covers
grep '^COVER_TOKEN_SECRET=' ../../../.env | cut -d= -f2- | npx wrangler secret put COVER_TOKEN_SECRET
npx wrangler deploy
```

(From the repo root, `npm --workspace @liner/covers-worker run deploy` also
works for the deploy step — `npm run` sets the cwd to the workspace. Only
`deploy`/`dev`/`typecheck`/`sign-token` are wired as scripts; `secret put` is a
one-off you run directly as above.)

`wrangler.toml` declares the `covers.tryliner.fun` custom domain; the zone
`tryliner.fun` must be on the same Cloudflare account. Rotating the secret =
re-run the `secret put` step with a new value (and update `.env` + `.dev.vars`);
existing signed tokens stop validating the moment the secret changes.

## Local dev

```powershell
# .dev.vars already holds COVER_TOKEN_SECRET (mirrors .env); wrangler loads it.
npm --workspace @liner/covers-worker run dev        # http://localhost:8787
npm --workspace @liner/covers-worker run typecheck

# Mint a token to hit it with. Pass the same secret the Worker uses; omit it for
# an unsigned token (only accepted when the Worker's secret is unset):
cd apps/workers/covers
$secret = ((Get-Content .dev.vars | Select-String '^COVER_TOKEN_SECRET=').Line -split '=',2)[1].Trim('"')
node scripts/sign-token.mjs "https://lh3.googleusercontent.com/<id>" 512 $secret
# → prints: path: /c/<token>?size=512
curl.exe "http://localhost:8787/c/<token>?size=512" -i --output cover.jpg
```

Expected: `200` + `content-type: image/...` for a valid signed token; `403`
`Invalid token.` if the signature is wrong/absent while the secret is set.

---

## Pencilled-in follow-ups (NOT implemented here)

These belong to the API and client, tracked here so the contract stays in one
place.

### API (`apps/api` + `packages/core`)

Cover responses gain a fallback alongside the existing `coverUrl`:

```jsonc
{
  "coverUrl": "https://lh3.googleusercontent.com/…",       // direct Google
  "coverFallbackUrl": "https://covers.tryliner.fun/c/<token>?size=512"
}
```

- Build the token where covers are currently produced —
  `packages/core/src/modules/catalog/providers/innertube/innertube-thumbnail.ts`
  (`coverFromThumbnail` / `toSquareArtworkUrl`). Encode the size-agnostic URL so
  one cover yields one stable token.
- `ApiCover` (in `apps/client/src/lib/api.ts`) grows an optional
  `fallbackUrl`; `toClientTrack` (`apps/client/src/lib/track.ts`) maps it to
  `coverFallbackUrl` on the client `Track`.

### Client (`apps/client`)

Add `fallbackSrc` to the shared cover pipeline: `coverArt.ts` +
`useCoverReady` load `coverUrl` first and, on `error`, retry with
`coverFallbackUrl` before settling. A thin `<CoverImage src fallbackSrc />`
wrapper over `next/image` keeps call sites clean:

```tsx
<CoverImage src={track.coverUrl} fallbackSrc={track.coverFallbackUrl} />
```

The cover service worker (`public/cover-sw.js`) allowlist should add
`covers.tryliner.fun` so proxied covers are cached/deduped like direct ones.
