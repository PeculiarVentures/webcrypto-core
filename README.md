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

Custom providers can override `getKeyLength()` and register through `subtle.providers.set(provider)` without changing `SubtleCrypto`. The method receives the normalized target algorithm and returns a bit length or `null`. Existing providers inherit the previous `algorithm.length || 512` behavior, so this API does not require an implementation change in existing extensions. New providers should override it with their algorithm's length rules.

The common derivation wrapper rejects results shorter than an explicitly requested length with `OperationError`, including when derivation is called internally by `deriveKey()`. A separate overridable `getDeriveBitsLength()` hook resolves the backend request before source validation, while result validation uses the original requested length. Its options identify internal `deriveKey()` calls with `deriveKey: true`. By default, internal full-secret requests retain the historical 512-bit request for existing custom source providers; direct `deriveBits(null)` calls still pass `null` through.

ECDH uses the byte-rounded size from `EcCurves` for full-secret requests, and X25519/ECDH-ES use their fixed secret sizes. For unregistered ECDH curves, internal `deriveKey()` calls retain the historical 512-bit backend request; direct `deriveBits(null)` calls still pass `null` through. Registering curve metadata or overriding the source hook enables exact full-secret sizing for custom curves without changing existing extensions. HKDF/PBKDF2 source operations require an explicit length.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, checks and release process.
