<h1 align="center">
  webcrypto-core
</h1>

<div align="center">

![NPM License](https://img.shields.io/npm/l/webcrypto-core)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/PeculiarVentures/webcrypto-core/publish.yml?branch=master&label=publish)
[![npm version](https://img.shields.io/npm/v/webcrypto-core.svg)](https://www.npmjs.com/package/webcrypto-core)
![Coveralls](https://img.shields.io/coverallsCoverage/github/PeculiarVentures/webcrypto-core)
[![npm downloads](https://img.shields.io/npm/dm/webcrypto-core.svg)](https://www.npmjs.com/package/webcrypto-core)

</div>

We have created a number of WebCrypto polyfills including: [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl), [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11), and [webcrypto-liner](https://github.com/PeculiarVentures/webcrypto-liner). `webcrypto-core` was designed to be a common layer to be used by all of these libraries for input validation.

Unless you intend to create a WebCrypto polyfill this library is probably not useful to you.

## Install

```sh
npm install webcrypto-core
```

The package is ESM-only with TypeScript declarations, and requires Node.js `^20.19.0 || >=22.12.0`. CommonJS code can still `require()` it on those versions. `@peculiar/asn1-schema`, `@peculiar/json-schema` and `asn1js` are peer dependencies; npm 7+ installs them automatically.

## Breaking Changes In v2

v2 is ESM-only and requires Node.js `^20.19.0 || >=22.12.0` (1.x declared no range). CommonJS code can still `require("webcrypto-core")` on these versions; Node.js 22.0–22.11 can't. Apart from `BufferSourceConverter` and `PemConverter`, the public API is unchanged: the same exports and type declarations as 1.9.2.

- **TypeScript compiling to CommonJS:** use `"module": "node20"` or `"nodenext"` (`node16` fails with TS1479). ESM and bundler setups need no changes. Consumers don't need `experimentalDecorators`.
- **Jest in CommonJS mode:** switch to ESM mode or Vitest, or add `webcrypto-core` and its `@peculiar/*` and `asn1js` dependencies to `transformIgnorePatterns`.
- **Deep imports** (`webcrypto-core/build/...`) stay blocked by `exports`; import from `webcrypto-core`.
- **Peer dependencies:** `@peculiar/asn1-schema` `^3.0.0`, `@peculiar/json-schema` `^3.0.0` and `asn1js` `^4.0.0`. webcrypto-core registers its ASN.1 and JWK classes in the schema storages of those packages, so an app needs exactly one copy of each; a conflicting major now fails at install (`ERESOLVE`) instead of at runtime. Libraries built on the older majors (`@peculiar/webcrypto` 1, `@peculiar/x509` 2) have to move together.
- **`BufferSourceConverter` is no longer exported.** It was a re-export of the deprecated `@peculiar/utils/legacy` class. Use the functions from `@peculiar/utils/bytes` instead: `toArrayBuffer`, `toUint8Array`, `isBufferSource`, `equal` (was `isEqual`) and `concat` (takes an array).
- **`PemConverter` is removed.** Use `pem` from `@peculiar/utils/pem`:
  - `toArrayBuffer(text)` / `toUint8Array(text)` → `pem.decodeFirst(text)`. It returns a `Uint8Array`, reads the first block of a bundle, skips text before the block and throws if there's no block. Base64 with no BEGIN/END lines, or mismatched BEGIN/END labels, now throw. Single-line PEM, which `PemConverter` decoded to empty bytes, now decodes correctly.
  - `fromBufferSource(data, tag)` → `pem.encode(label, data)`. The label is used as given (pass `"PUBLIC KEY"`, not `"public key"`) and the output ends with a newline.
  - `isPEM`, `getTagName`, `hasTagName`, `isCertificate`, `isCertificateRequest`, `isCRL`, `isPublicKey` → `pem.decode(text)` returns the blocks with their `label`, and `pem.find(text, "CERTIFICATE")` finds a block by label. Labels compare case-sensitively.
- **`@peculiar/utils` 4** replaces 2 (same functions, ESM-only). JWK import still accepts only unpadded base64url, as in 1.x.

## Example

The example below implements a minimal WebCrypto interface with a SHA-1 provider.

```js
import * as nodeCrypto from "node:crypto";
import * as core from "webcrypto-core";

class Sha1Provider extends core.ProviderCrypto {
  name = "SHA-1";
  usages = [];

  async onDigest(algorithm, data) {
    const hash = nodeCrypto.createHash("sha1").update(new Uint8Array(data)).digest();
    return new Uint8Array(hash).buffer;
  }
}

class SubtleCrypto extends core.SubtleCrypto {
  constructor() {
    super();

    // Add SHA-1 provider to SubtleCrypto
    this.providers.set(new Sha1Provider());
  }
}

class Crypto extends core.Crypto {
  subtle = new SubtleCrypto();

  getRandomValues(array) {
    return nodeCrypto.getRandomValues(array);
  }
}

const crypto = new Crypto();
const hash = await crypto.subtle.digest("SHA-1", new TextEncoder().encode("TEST MESSAGE"));
console.log(Buffer.from(hash).toString("hex")); // dbca505deb07e1612d944a69c0c851f79f3a4a60
```

## Derived Key Lengths

`SubtleCrypto.deriveKey()` asks the target provider's `getKeyLength(algorithm)` how many bits to request from the source provider. AES uses the requested key size, HMAC uses an explicit size or the hash block size, and HKDF/PBKDF2 return `null` to import the full shared secret.

Custom providers can override `getKeyLength()` for target sizing and `getDeriveBitsLength()` for backend sizing, then register through `subtle.providers.set(provider)` without changing `SubtleCrypto`. Both hooks have concrete compatibility defaults, so existing extensions do not need to implement new methods. See their TSDoc for normalization order and legacy fallback details.

## Upgrading From 2.0.x

The provider API additions preserve existing extension hooks, but the following standards corrections change runtime behavior. Applications that re-derive keys for stored data or existing MACs should retain a versioned derivation profile rather than silently adopting new defaults.

- **HMAC SHA-384/SHA-512 defaults change from 512 to 1024 bits.** This affects `getDefaultLength()` and downstream `generateKey()` and `deriveKey()` calls that omit `length`. Re-derived keys and MACs can change. Specify `length: 512` to retain the old default size for key generation or KDF-based derivation. For old ECDH calls that silently returned a shorter key, use the actual previous key length instead (see below).
- **ECDH P-521 to HKDF/PBKDF2 uses all 66 bytes of the shared secret instead of the previous 64-byte truncation.** Subsequent keys change, so previously encrypted data requires the original derivation profile. To reproduce that profile, explicitly call `deriveBits(..., 512)`, then import those bytes as the HKDF/PBKDF2 key. New profiles should use the full secret.
- **Requests exceeding the shared secret now reject with `OperationError`.** This includes `deriveKey(ECDH P-256 → HMAC SHA-256)` without a length, which requests the 512-bit HMAC default from a 256-bit secret. To reproduce a previously shortened key, explicitly request its actual old length (256 bits in this example). For new profiles, use an explicit supported key length, or a KDF when the protocol requires a longer key.
- **HKDF/PBKDF2 to HKDF/PBKDF2 through `deriveKey()` now rejects with `OperationError`.** The target requests a `null` length, which these source KDFs prohibit. For an explicitly defined KDF chain, call `deriveBits()` with a numeric length and import the result as the target key. Use 512 bits to reproduce the old internal request.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, checks and release process.
