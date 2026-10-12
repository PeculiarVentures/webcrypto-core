import { describe, it, expect } from "vitest";
import { CryptoKey, ProviderCrypto, SubtleCrypto } from "./index";

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
      expect(!!res).toBe(true);
    });
  });

  describe("digest", () => {
    it("correct values", async () => {
      const res = await subtle.digest("test", new Uint8Array(0));
      expect(!!res).toBe(true);
    });
  });

  describe("sign", () => {
    it("correct values", async () => {
      const res = await subtle.sign(
        {
          name: "test",
          hash: "SHA-1",
        } as any,
        key,
        new Uint8Array(0),
      );
      expect(!!res).toBe(true);
    });
  });

  describe("verify", () => {
    it("correct values", async () => {
      const res = await subtle.verify(
        {
          name: "test",
          hash: { name: "SHA-1" },
        } as any,
        key,
        new ArrayBuffer(0),
        new Uint8Array(0),
      );
      expect(!!res).toBe(true);
    });
  });

  describe("encrypt", () => {
    it("correct values", async () => {
      const res = await subtle.encrypt("test", key, new Uint8Array(0));
      expect(!!res).toBe(true);
    });
  });

  describe("decrypt", () => {
    it("correct values", async () => {
      const res = await subtle.decrypt("test", key, new Uint8Array(0));
      expect(!!res).toBe(true);
    });
  });

  describe("deriveBits", () => {
    it("correct values", async () => {
      const res = await subtle.deriveBits("test", key, 128);
      expect(!!res).toBe(true);
    });
  });

  describe("deriveKey", () => {
    it("correct values", async () => {
      const res = await subtle.deriveKey(
        "test",
        key,
        {
          name: "test",
          length: 128,
        } as any,
        false,
        ["verify"],
      );
      expect(!!res).toBe(true);
    });
  });

  describe("exportKey", () => {
    it("correct values", async () => {
      const res = await subtle.exportKey("raw", key);
      expect(!!res).toBe(true);
    });

    it("throws for invalid key format", async () => {
      await expect(subtle.exportKey("invalid_format" as any, key)).rejects.toThrow(TypeError);
    });

    it("throws for key not of expected type", async () => {
      const key = new CryptoKey();
      key.type = "wrong_type" as any;
      const promise = subtle.exportKey("raw", key);
      await expect(promise).rejects.toBeInstanceOf(DOMException);
      await expect(promise).rejects.toThrow("The key is not of the expected type");
    });
  });

  describe("importKey", () => {
    it("correct values", async () => {
      const res = await subtle.importKey("raw", new ArrayBuffer(0), "test", false, ["sign"]);
      expect(!!res).toBe(true);
    });

    it("json", async () => {
      const res = await subtle.importKey("jwk", { kty: "RSA" }, "test", false, ["sign"]);
      expect(!!res).toBe(true);
    });

    it("Uint8Array", async () => {
      const res = await subtle.importKey("raw", new Uint8Array(10), "test", false, ["sign"]);
      expect(!!res).toBe(true);
    });

    it("Buffer", async () => {
      const res = await subtle.importKey("raw", Buffer.alloc(10), "test", false, ["sign"]);
      expect(!!res).toBe(true);
    });

    it("ArrayBuffer", async () => {
      const res = await subtle.importKey("raw", new ArrayBuffer(10), "test", false, ["sign"]);
      expect(!!res).toBe(true);
    });

    it("throws for non-object JWK", async () => {
      await expect(subtle.importKey("jwk", new ArrayBuffer(0), "test", false, ["sign"])).rejects.toThrow(TypeError);
    });

    it("throws for non-BufferSource for non-JWK formats", async () => {
      await expect(subtle.importKey("spki", {}, "test", false, ["sign"])).rejects.toThrow(TypeError);
    });

    it("throws for invalid format", async () => {
      await expect(subtle.importKey("invalid_format", {}, "test", false, ["sign"])).rejects.toThrow(TypeError);
    });
  });

  describe("wrapKey", () => {
    it("correct values", async () => {
      const res = await subtle.wrapKey("raw", key, key, "test");
      expect(!!res).toBe(true);
    });
  });

  describe("unwrapKey", () => {
    it("correct values", async () => {
      const res = await subtle.unwrapKey("raw", new ArrayBuffer(0), key, "test", "test", false, ["deriveKey"]);
      expect(!!res).toBe(true);
    });
  });

  describe("checkRequiredArguments", () => {
    it("error if less than required", async () => {
      await expect(subtle.digest.apply(subtle, ["test"] as unknown as [AlgorithmIdentifier, BufferSource])).rejects.toThrow(TypeError);
    });

    it("no error if greater than required", async () => {
      await (subtle.digest as (...args: unknown[]) => Promise<ArrayBuffer>).call(subtle, "test", new Uint8Array(0), 1, 2, 3);
    });
  });

  describe("getProvider", () => {
    it("error if there is not provider with given name", async () => {
      await expect(subtle.digest("wrong", new Uint8Array(0))).rejects.toThrow();
    });
  });

  describe("prepareData", () => {
    it("error if wrong data", async () => {
      await expect(subtle.digest("test", [1, 2, 3, 4] as any)).rejects.toThrow();
    });
    it("from Buffer", async () => {
      await subtle.digest("test", Buffer.from([1, 2, 3, 4]));
    });
  });
});
