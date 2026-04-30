/* eslint-disable prefer-spread */
import assert from "node:assert";
import {
  CryptoKey, ProviderCrypto, SubtleCrypto,
} from "../src";

describe("SubtleCrypto", () => {
  class TestProvider extends ProviderCrypto {
    public name = "TEST";
    public usages: KeyUsage[] = ["sign", "verify", "deriveKey", "deriveBits", "encrypt", "decrypt", "wrapKey", "unwrapKey"];

    public override async onDigest(_algorithm: Algorithm, _data: ArrayBuffer): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onGenerateKey(_algorithm: Algorithm, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
      return key;
    }

    public override async onSign(_algorithm: Algorithm, _sKey: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onVerify(_algorithm: Algorithm, _sKey: CryptoKey, _signature: ArrayBuffer, _data: ArrayBuffer): Promise<boolean> {
      return true;
    }

    public override async onEncrypt(_algorithm: Algorithm, _sKey: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onDecrypt(_algorithm: Algorithm, _sKey: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onDeriveBits(_algorithm: Algorithm, _sKey: CryptoKey, _length: number): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onExportKey(_format: KeyFormat, _sKey: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onImportKey(_format: KeyFormat, _keyData: JsonWebKey | ArrayBuffer, _algorithm: Algorithm, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
      return key;
    }
  }

  class TestSubtleCrypto extends SubtleCrypto {
    constructor() {
      super();

      this.providers.set(new TestProvider());
    }
  }

  const subtle = new TestSubtleCrypto();
  const key = new CryptoKey();
  key.algorithm = { name: "TEST" };
  key.type = "secret";
  key.usages = ["sign", "verify", "deriveKey", "deriveBits", "encrypt", "decrypt", "wrapKey", "unwrapKey"];
  key.extractable = true;

  describe("generateKey", () => {
    it("correct values", async () => {
      const res = await subtle.generateKey("test", false, ["sign"]);
      assert.equal(!!res, true);
    });
  });

  describe("digest", () => {
    it("correct values", async () => {
      const res = await subtle.digest("test", new Uint8Array(0));
      assert.equal(!!res, true);
    });
  });

  describe("sign", () => {
    it("correct values", async () => {
      const res = await subtle.sign({
        name: "test", hash: "SHA-1",
      } as any, key, new Uint8Array(0));
      assert.equal(!!res, true);
    });
  });

  describe("verify", () => {
    it("correct values", async () => {
      const res = await subtle.verify({
        name: "test", hash: { name: "SHA-1" },
      } as any, key, new ArrayBuffer(0), new Uint8Array(0));
      assert.equal(!!res, true);
    });
  });

  describe("encrypt", () => {
    it("correct values", async () => {
      const res = await subtle.encrypt("test", key, new Uint8Array(0));
      assert.equal(!!res, true);
    });
  });

  describe("decrypt", () => {
    it("correct values", async () => {
      const res = await subtle.decrypt("test", key, new Uint8Array(0));
      assert.equal(!!res, true);
    });
  });

  describe("deriveBits", () => {
    it("correct values", async () => {
      const res = await subtle.deriveBits("test", key, 128);
      assert.equal(!!res, true);
    });
  });

  describe("deriveKey", () => {
    it("correct values", async () => {
      const res = await subtle.deriveKey("test", key, {
        name: "test", length: 128,
      } as any, false, ["verify"]);
      assert.equal(!!res, true);
    });
  });

  describe("exportKey", () => {
    it("correct values", async () => {
      const res = await subtle.exportKey("raw", key);
      assert.equal(!!res, true);
    });

    it("throws for invalid key format", async () => {
      await assert.rejects(
        subtle.exportKey("invalid_format" as any, key),
        TypeError,
        "Invalid keyFormat argument",
      );
    });

    it("throws for key not of expected type", async () => {
      const key = new CryptoKey();
      key.type = "wrong_type" as any;
      await assert.rejects(
        subtle.exportKey("raw", key),
        (e: Error) => {
          assert.ok(e instanceof DOMException, "Error is not an instance of DOMException");
          assert.strictEqual(e.message, "The key is not of the expected type", "Error message is not as expected");
          return true;
        },
      );
    });
  });

  describe("importKey", () => {
    it("correct values", async () => {
      const res = await subtle.importKey("raw", new ArrayBuffer(0), "test", false, ["sign"]);
      assert.equal(!!res, true);
    });

    it("json", async () => {
      const res = await subtle.importKey("jwk", { kty: "RSA" }, "test", false, ["sign"]);
      assert.equal(!!res, true);
    });

    it("Uint8Array", async () => {
      const res = await subtle.importKey("raw", new Uint8Array(10), "test", false, ["sign"]);
      assert.equal(!!res, true);
    });

    it("Buffer", async () => {
      const res = await subtle.importKey("raw", Buffer.alloc(10), "test", false, ["sign"]);
      assert.equal(!!res, true);
    });

    it("ArrayBuffer", async () => {
      const res = await subtle.importKey("raw", new ArrayBuffer(10), "test", false, ["sign"]);
      assert.equal(!!res, true);
    });

    it("throws for non-object JWK", async () => {
      await assert.rejects(
        subtle.importKey("jwk", new ArrayBuffer(0), "test", false, ["sign"]),
        TypeError,
        "Key data must be an object for JWK import",
      );
    });

    it("throws for non-BufferSource for non-JWK formats", async () => {
      await assert.rejects(
        subtle.importKey("spki", {}, "test", false, ["sign"]),
        TypeError,
        "Key data must be a BufferSource for non-JWK formats",
      );
    });

    it("throws for invalid format", async () => {
      await assert.rejects(
        subtle.importKey("invalid_format", {}, "test", false, ["sign"]),
        TypeError,
        "The provided value is not of type '(ArrayBuffer or ArrayBufferView or JsonWebKey)'",
      );
    });
  });

  describe("wrapKey", () => {
    it("correct values", async () => {
      const res = await subtle.wrapKey("raw", key, key, "test");
      assert.equal(!!res, true);
    });
  });

  describe("unwrapKey", () => {
    it("correct values", async () => {
      const res = await subtle.unwrapKey("raw", new ArrayBuffer(0), key, "test", "test", false, ["deriveKey"]);
      assert.equal(!!res, true);
    });
  });

  describe("checkRequiredArguments", () => {
    it("error if less than required", async () => {
      await assert.rejects(subtle.digest.apply(subtle, ["test"] as unknown as [AlgorithmIdentifier, BufferSource]), TypeError);
    });

    it("no error if greater than required", async () => {
      await assert.doesNotReject(subtle.digest.apply(subtle, ["test", new Uint8Array(0), 1, 2, 3]));
    });
  });

  describe("getProvider", () => {
    it("error if there is not provider with given name", async () => {
      await assert.rejects(subtle.digest("wrong", new Uint8Array(0)));
    });
  });

  describe("prepareData", () => {
    it("error if wrong data", async () => {
      await assert.rejects(subtle.digest("test", [1, 2, 3, 4] as any));
    });
    it("from Buffer", async () => {
      await subtle.digest("test", Buffer.from([1, 2, 3, 4]));
    });
  });
});
