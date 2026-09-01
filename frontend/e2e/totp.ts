import { createHmac } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input: string): Buffer {
  const clean = input.replace(/=+$/, "").toUpperCase().replace(/\s/g, "");
  let bits = "";
  for (const char of clean) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value === -1) throw new Error(`totp.ts: invalid base32 character in secret: ${char}`);
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

/**
 * RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30s step) -- Keycloak's own default
 * OTP policy, confirmed live against this repo's real running Keycloak
 * 26.2 (Milestone JJJJ: the real CONFIGURE_TOTP page's own "Algorithm:
 * SHA1 / Digits: 6 / Interval: 30" text, read directly, not assumed from
 * the RFC alone). No external dependency (`pyotp` is what
 * `poc/auth_flow/auth_helpers.py`'s Python precedent uses; this is the
 * same algorithm, implemented with Node's built-in `crypto` so this
 * TypeScript suite doesn't need a new npm dependency for one small,
 * stable, unlikely-to-change primitive).
 */
export function generateTotp(base32Secret: string, stepSeconds = 30, digits = 6): string {
  const key = base32Decode(base32Secret);
  const counter = Math.floor(Date.now() / 1000 / stepSeconds);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter % 0x100000000, 4);
  const hmac = createHmac("sha1", key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (binCode % 10 ** digits).toString().padStart(digits, "0");
}
