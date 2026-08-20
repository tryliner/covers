#!/usr/bin/env node
/**
 * Mint a covers-proxy token for manual testing / deploy verification.
 *
 * Produces the exact token the Worker expects:
 *   payload = base64url(JSON({ u, s }))
 *   token   = payload            (when no secret — signing disabled)
 *           = payload + "." + base64url(HMAC_SHA256(secret, payload))
 *
 * Usage:
 *   # unsigned (secret disabled on the Worker)
 *   node scripts/sign-token.mjs "https://lh3.googleusercontent.com/abc" 512
 *
 *   # signed — secret from arg or COVER_TOKEN_SECRET env
 *   COVER_TOKEN_SECRET=... node scripts/sign-token.mjs "https://lh3.googleusercontent.com/abc" 512
 *   node scripts/sign-token.mjs "https://lh3.googleusercontent.com/abc" 512 "my-secret"
 *
 * Prints the path to hit, e.g. `/c/<token>?size=512`.
 */
import { createHmac } from "node:crypto";

const [, , url, sizeArg, secretArg] = process.argv;
const secret = secretArg ?? process.env.COVER_TOKEN_SECRET ?? "";
const size = Number(sizeArg) || 512;

if (!url) {
  console.error('Usage: node scripts/sign-token.mjs "<https-cover-url>" [size] [secret]');
  process.exit(1);
}

// Match the API: strip trailing size options so one cover yields one token.
// i.ytimg.com keeps size in the path, so leave it whole.
const host = new URL(url).hostname;
const eq = url.indexOf("=");
const sizeAgnostic = host === "i.ytimg.com" || eq === -1 ? url : url.slice(0, eq);

const payload = Buffer.from(JSON.stringify({ u: sizeAgnostic, s: size }), "utf8").toString("base64url");
const token = secret
  ? `${payload}.${createHmac("sha256", secret).update(payload).digest("base64url")}`
  : payload;

console.log(`token: ${token}`);
console.log(`path:  /c/${token}?size=${size}`);
console.log(secret ? "(signed)" : "(unsigned — Worker must have COVER_TOKEN_SECRET unset)");
