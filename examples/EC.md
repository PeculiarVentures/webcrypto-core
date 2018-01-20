# EC

- [ECDSA](#ecdsa)
- [ECDH](#ecdh)

## <a name="ecdsa"></a>ECDSA

- [generateKey](#ecdsa_generateKey)
- [exportKey](#ecdsa_exportKey)
- [importKey](#ecdsa_importKey)
- [sign](#ecdsa_sign)
- [verify](#ecdsa_verify)
    
### <a name="ecdsa_generateKey"></a>generateKey

> NOTE: 25519 named curve is not a W3 standard

```js
crypto.subtle.generateKey(
    {
        name: "ECDSA",
        namedCurve: "P-256" // can be P-256, P-384, P-521 or 25519
    },
    false,
    ["sign", "verify"],
)
.then((keyPair) => {
    console.log(keyPair.privateKey);
    console.log(keyPair.publicKey);
});
```

### <a name="ecdsa_exportKey"></a>exportKey

```js
crypto.subtle.exportKey(
    "jwk", // can be pkcs8 for private key, spki and raw for public key, jwk for both keys
    privateKey,
)
.then((jwk) => {
    console.log(jwk);
});
```

### <a name="ecdsa_importKey"></a>importKey

```js
crypto.subtle.importKey(
    "jwk", // can be pkcs8 for private key, spki and raw for public key, jwk for both keys
    jwk,
    {
        name: "ECDSA",
        namedCurve: "P-256" // can be P-256, P-384, P-521 or 25519
    },
    false,
    ["verify"],
)
.then((publicKey) => {
    console.log(publicKey);
});
```

### <a name="ecdsa_sign"></a>Signing

```js
crypto.subtle.sign(
    {
        name: "ECDSA",
        hash: "SHA-256",
    },
    privateKey,
    data, // ArrayBuffer or ArrayBufferView
)
.then((signature) => {
    console.log(new Uint8Array(signature));
})
```

### <a name="ecdsa_verify"></a>Verifying

```js
crypto.subtle.verify(
    {
        name: "ECDSA",
        hash: "SHA-256",
    },
    publicKey,
    signature, // ArrayBuffer or ArrayBufferView
    data, // ArrayBuffer or ArrayBufferView
)
.then((ok) => {
    console.log(ok);
})
```

## <a name="ecdh"></a>ECDH

- [generateKey](#ecdh_generateKey)
- [exportKey](#ecdh_exportKey)
- [importKey](#ecdh_importKey)
- [deriveKey](#ecdh_deriveKey)
- [deriveBits](#ecdh_deriveBits)

### <a name="ecdh_generateKey"></a>generateKey

> NOTE: 25519 named curve is not a W3 standard

```js
crypto.subtle.generateKey(
    {
        name: "ECDSA",
        namedCurve: "P-256" // can be P-256, P-384, P-521 or 25519
    },
    false,
    ["deriveKey", "deriveBits"],
)
.then((keyPair) => {
    console.log(keyPair.privateKey);
    console.log(keyPair.publicKey);
});
```

### <a name="ecdh_exportKey"></a>Export key

```js
crypto.subtle.exportKey(
    "jwk", // can be pkcs8 for private key, spki and raw for public key, jwk for both keys
    privateKey,
)
.then((jwk) => {
    console.log(jwk);
});
```

### <a name="ecdh_importKey"></a>importKey

```js
crypto.subtle.importKey(
    "jwk", // can be pkcs8 for private key, spki and raw for public key, jwk for both keys
    jwk,
    {
        name: "ECDH",
        namedCurve: "P-256" // can be P-256, P-384, P-521 or 25519
    },
    false,
    ["verify"],
)
.then((publicKey) => {
    console.log(publicKey);
});
```

### <a name="ecdh_deriveKey"></a>вукшмуЛун

```js
crypto.subtle.deriveKey(
    {
        name: "ECDH",
        public: publicKey, // ECDH public key
    },
    privateKey,
    {
        name: "AES-CBC",
        length: 256,
    },
    false,
    ["encrypt", "decrypt"],
)
.then((derivedKey) => {
    console.log(derivedKey);
});
```

### <a name="ecdh_deriveBits"></a>deriveBits

```js
crypto.subtle.deriveBits(
    {
        name: "ECDH",
        public: publicKey, // ECDH public key
    },
    privateKey,
    256,
)
.then((derivedBits) => {
    console.log(new Uint8Array(derivedBits));
});
```