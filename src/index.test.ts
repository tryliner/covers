import { describe, expect, it } from "vitest";
import { decodeToken, splitToken, verifyToken, type Env } from "./index";

const SECRET = "test-secret-abc";

function toBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const b of view) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function payloadFor(url: string, size = 512): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify({ u: url, s: size })));
}

/** Mirror of the Worker's signing scheme, used to forge valid/invalid tokens. */
async function sign(payload: string, secret = SECRET): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return `${payload}.${toBase64Url(sig)}`;
}

const withSecret: Env = { COVER_TOKEN_SECRET: SECRET };
const noSecret: Env = {};

describe("verifyToken — secret unset (signing disabled)", () => {
  it("accepts any decodable token so the unsigned client keeps working", async () => {
    const unsigned = payloadFor("https://lh3.googleusercontent.com/abc");
    expect(await verifyToken(unsigned, noSecret)).toBe(true);
  });
});

describe("verifyToken — secret set (signing enforced)", () => {
  it("accepts a correctly signed token", async () => {
    const token = await sign(payloadFor("https://lh3.googleusercontent.com/abc"));
    expect(await verifyToken(token, withSecret)).toBe(true);
  });

  it("rejects an unsigned token (no signature suffix)", async () => {
    const unsigned = payloadFor("https://lh3.googleusercontent.com/abc");
    expect(await verifyToken(unsigned, withSecret)).toBe(false);
  });

  it("rejects a tampered payload (changed bytes → signature no longer matches)", async () => {
    const token = await sign(payloadFor("https://lh3.googleusercontent.com/abc"));
    const { signature } = splitToken(token);
    // Swap in a different payload but keep the original signature.
    const forged = `${payloadFor("https://lh3.googleusercontent.com/EVIL")}.${signature}`;
    expect(await verifyToken(forged, withSecret)).toBe(false);
  });

  it("rejects a token whose signature bytes were flipped", async () => {
    const token = await sign(payloadFor("https://lh3.googleusercontent.com/abc"));
    const { payload } = splitToken(token);
    const bad = `${payload}.${toBase64Url(new Uint8Array(32))}`; // all-zero sig
    expect(await verifyToken(bad, withSecret)).toBe(false);
  });

  it("rejects a token signed with a different secret", async () => {
    const token = await sign(payloadFor("https://lh3.googleusercontent.com/abc"), "other-secret");
    expect(await verifyToken(token, withSecret)).toBe(false);
  });

  it("rejects a signature that is not valid base64url", async () => {
    const payload = payloadFor("https://lh3.googleusercontent.com/abc");
    expect(await verifyToken(`${payload}.@@@not-base64@@@`, withSecret)).toBe(false);
  });
});

describe("splitToken / decodeToken", () => {
  it("splits <payload>.<sig> and treats a dotless token as unsigned", () => {
    expect(splitToken("abc.def")).toEqual({ payload: "abc", signature: "def" });
    expect(splitToken("abc")).toEqual({ payload: "abc", signature: null });
  });

  it("decodes the payload half and ignores the signature suffix", () => {
    const decoded = decodeToken(payloadFor("https://lh3.googleusercontent.com/abc", 256));
    expect(decoded).toEqual({ url: "https://lh3.googleusercontent.com/abc", size: 256 });
  });
});
