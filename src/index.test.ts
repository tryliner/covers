import { describe, expect, it } from "vitest";
import { ALLOWED_HOSTS, decodeToken, splitToken, verifyToken, type Env } from "./index";

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
    const unsigned = payloadFor("https://i1.sndcdn.com/artworks-abc-t500x500.jpg");
    expect(await verifyToken(unsigned, noSecret)).toBe(true);
  });
});

describe("verifyToken — secret set (signing enforced)", () => {
  it("accepts a correctly signed token", async () => {
    const token = await sign(payloadFor("https://i1.sndcdn.com/artworks-abc-t500x500.jpg"));
    expect(await verifyToken(token, withSecret)).toBe(true);
  });

  it("rejects an unsigned token (no signature suffix)", async () => {
    const unsigned = payloadFor("https://i1.sndcdn.com/artworks-abc-t500x500.jpg");
    expect(await verifyToken(unsigned, withSecret)).toBe(false);
  });

  it("rejects a tampered payload (changed bytes → signature no longer matches)", async () => {
    const token = await sign(payloadFor("https://i1.sndcdn.com/artworks-abc-t500x500.jpg"));
    const { signature } = splitToken(token);
    // Swap in a different payload but keep the original signature.
    const forged = `${payloadFor("https://i1.sndcdn.com/artworks-EVIL-t500x500.jpg")}.${signature}`;
    expect(await verifyToken(forged, withSecret)).toBe(false);
  });

  it("rejects a token whose signature bytes were flipped", async () => {
    const token = await sign(payloadFor("https://i1.sndcdn.com/artworks-abc-t500x500.jpg"));
    const { payload } = splitToken(token);
    const bad = `${payload}.${toBase64Url(new Uint8Array(32))}`; // all-zero sig
    expect(await verifyToken(bad, withSecret)).toBe(false);
  });

  it("rejects a token signed with a different secret", async () => {
    const token = await sign(payloadFor("https://i1.sndcdn.com/artworks-abc-t500x500.jpg"), "other-secret");
    expect(await verifyToken(token, withSecret)).toBe(false);
  });

  it("rejects a signature that is not valid base64url", async () => {
    const payload = payloadFor("https://i1.sndcdn.com/artworks-abc-t500x500.jpg");
    expect(await verifyToken(`${payload}.@@@not-base64@@@`, withSecret)).toBe(false);
  });
});

describe("splitToken / decodeToken", () => {
  it("splits <payload>.<sig> and treats a dotless token as unsigned", () => {
    expect(splitToken("abc.def")).toEqual({ payload: "abc", signature: "def" });
    expect(splitToken("abc")).toEqual({ payload: "abc", signature: null });
  });

  it("decodes the payload half and ignores the signature suffix", () => {
    const decoded = decodeToken(payloadFor("https://i1.sndcdn.com/artworks-abc-t500x500.jpg", 256));
    expect(decoded).toEqual({ url: "https://i1.sndcdn.com/artworks-abc-t500x500.jpg", size: 256 });
  });
});

describe("ALLOWED_HOSTS", () => {
  it("allows soundcloud image and avatar domains", () => {
    expect(ALLOWED_HOSTS.has("i1.sndcdn.com")).toBe(true);
    expect(ALLOWED_HOSTS.has("i2.sndcdn.com")).toBe(true);
    expect(ALLOWED_HOSTS.has("i3.sndcdn.com")).toBe(true);
    expect(ALLOWED_HOSTS.has("i4.sndcdn.com")).toBe(true);
    expect(ALLOWED_HOSTS.has("img.sndcdn.com")).toBe(true);
    expect(ALLOWED_HOSTS.has("a1.sndcdn.com")).toBe(true);
  });

  it("disallows old youtube domains", () => {
    expect(ALLOWED_HOSTS.has("i.ytimg.com")).toBe(false);
    expect(ALLOWED_HOSTS.has("yt3.ggpht.com")).toBe(false);
    expect(ALLOWED_HOSTS.has("lh3.googleusercontent.com")).toBe(false);
    expect(ALLOWED_HOSTS.has("yt3.googleusercontent.com")).toBe(false);
  });
});
