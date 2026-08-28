// Independent RFC 8785 (JSON Canonicalization Scheme) + SHA-256 implementation.
//
// The oracle's whole trust story rests on findings_hash: the free receipt
// commits to a hash of the findings array, and the paid tier must return
// findings that hash to the same value. A buyer who checks that by importing
// the seller's canonicalizer has not checked anything - a seller that ships a
// buggy or dishonest canonicalizer would pass its own check. This file is
// written from the RFC 8785 text, independently of anything under
// the oracle, so it can actually catch that failure mode.
//
// RFC 8785 requires: object keys sorted by UTF-16 code unit, no insignificant
// whitespace, and numbers formatted per ECMAScript's Number::toString - which
// is exactly what JSON.stringify already does for finite numbers.

function canonicalValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalValue).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const members = keys.map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key])}`);
    return "{" + members.join(",") + "}";
  }
  throw new TypeError(`cannot canonicalize a value of type ${typeof value}`);
}

export function canonicalize(value) {
  return canonicalValue(value);
}

export async function sha256Canonical(value) {
  const bytes = new TextEncoder().encode(canonicalize(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}
