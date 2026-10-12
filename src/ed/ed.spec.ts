import { describe, it, expect } from "vitest";
import { AsnConvert, AsnSerializer } from "@peculiar/asn1-schema";
import * as encoding from "@peculiar/utils/encoding";
import { EdPrivateKey, EdPublicKey, OneAsymmetricKey, PublicKeyInfo } from "../asn1";
import { CryptoKey, Ed25519Provider, X25519Provider } from "../index";

describe("ED", () => {
  describe("asn", () => {
    it("spki - jwk", () => {
      const pem = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

      const keyInfo = AsnConvert.parse(encoding.base64.decode(pem), PublicKeyInfo);
      const key = new EdPublicKey(keyInfo.publicKey);
      const jwk = key.toJSON();

      const key2 = new EdPublicKey();
      key2.fromJSON(jwk);
      expect(encoding.base64.encode(AsnSerializer.serialize(key2))).toBe(encoding.base64.encode(AsnSerializer.serialize(key)));
    });

    describe("pkcs8 -jwk", () => {
      it("without public key", () => {
        const pem = "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";

        const keyInfo = AsnConvert.parse(encoding.base64.decode(pem), OneAsymmetricKey);
        expect(keyInfo.publicKey).toBe(undefined);
        const key = AsnConvert.parse(keyInfo.privateKey, EdPrivateKey);
        const jwk = key.toJSON();

        const key2 = new EdPrivateKey();
        key2.fromJSON(jwk);
        expect(encoding.base64.encode(AsnSerializer.serialize(key2))).toBe(encoding.base64.encode(AsnSerializer.serialize(key)));
      });

      it("with public key", () => {
        const pem = "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhCoB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

        const keyInfo = AsnConvert.parse(encoding.base64.decode(pem), OneAsymmetricKey);
        expect(keyInfo.publicKey).toBeTruthy();
        const key = AsnConvert.parse(keyInfo.privateKey, EdPrivateKey);
        const jwk = key.toJSON();

        const key2 = new EdPrivateKey();
        key2.fromJSON(jwk);
        expect(encoding.base64.encode(AsnSerializer.serialize(key2))).toBe(encoding.base64.encode(AsnSerializer.serialize(key)));
      });
    });
  });

  describe("Ed25519", () => {
    class TestEd25519Provider extends Ed25519Provider {
      public override async onGenerateKey(_algorithm: Algorithm, extractable: boolean, _keyUsages: KeyUsage[], ..._args: any[]): Promise<CryptoKeyPair> {
        const privateKey = new CryptoKey();
        privateKey.algorithm = { name: "Ed25519" };
        privateKey.type = "private";
        privateKey.extractable = extractable;
        privateKey.usages = ["sign"];

        const publicKey = new CryptoKey();
        publicKey.algorithm = { name: "Ed25519" };
        publicKey.type = "public";
        publicKey.extractable = true;
        publicKey.usages = ["verify"];

        return {
          privateKey,
          publicKey,
        };
      }

      public async onSign(_algorithm: Algorithm, _key: CryptoKey, _data: ArrayBuffer, ..._args: any[]): Promise<ArrayBuffer> {
        return new ArrayBuffer(64);
      }

      public async onVerify(_algorithm: Algorithm, _key: CryptoKey, _signature: ArrayBuffer, _data: ArrayBuffer, ..._args: any[]): Promise<boolean> {
        return true;
      }
    }

    const provider = new TestEd25519Provider();

    describe("generateKey", () => {
      it("should generate key pair", async () => {
        const keys = (await provider.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
        expect("privateKey" in keys).toBeTruthy();
        expect("publicKey" in keys).toBeTruthy();
        expect(keys.privateKey.algorithm.name).toBe("Ed25519");
        expect(keys.privateKey.type).toBe("private");
        expect(keys.privateKey.extractable).toBe(true);
        expect(keys.privateKey.usages).toStrictEqual(["sign"]);
        expect(keys.publicKey.algorithm.name).toBe("Ed25519");
        expect(keys.publicKey.type).toBe("public");
        expect(keys.publicKey.extractable).toBe(true);
        expect(keys.publicKey.usages).toStrictEqual(["verify"]);
      });
      it("should throw error when algorithm is not correct", async () => {
        await expect(provider.generateKey({ name: "RSASSA-PKCS1-v1_5" }, true, ["sign", "verify"])).rejects.toMatchObject({ message: "Unrecognized name" });
      });
      it("should throw error when keyUsages is not correct", async () => {
        await expect(provider.generateKey({ name: "Ed25519" }, true, ["encrypt", "decrypt"])).rejects.toMatchObject({ message: "Cannot create a key using the specified key usages" });
      });
    });
    describe("sign", () => {
      it("should sign data", async () => {
        const keys = (await provider.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
        expect("privateKey" in keys).toBeTruthy();
        await provider.sign({ name: "Ed25519" }, keys.privateKey, new ArrayBuffer(32));
      });
      it("should throw error when algorithm is not correct", async () => {
        const keys = (await provider.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
        expect("privateKey" in keys).toBeTruthy();
        await expect(provider.sign({ name: "RSASSA-PKCS1-v1_5" }, keys.privateKey, new ArrayBuffer(32))).rejects.toMatchObject({ message: "Unrecognized name" });
      });
    });
    describe("verify", () => {
      it("should verify signature", async () => {
        const keys = (await provider.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
        expect("privateKey" in keys).toBeTruthy();
        const signature = new ArrayBuffer(64);
        const res = await provider.verify({ name: "Ed25519" }, keys.publicKey, signature, new ArrayBuffer(32));
        expect(res).toBe(true);
      });
      it("should throw error when algorithm is not correct", async () => {
        const keys = (await provider.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
        expect("privateKey" in keys).toBeTruthy();
        const signature = new ArrayBuffer(64);
        await expect(provider.verify({ name: "RSASSA-PKCS1-v1_5" }, keys.publicKey, signature, new ArrayBuffer(32))).rejects.toMatchObject({ message: "Unrecognized name" });
      });
    });
  });
  describe("X25519", () => {
    class TestX25519Provider extends X25519Provider {
      public override async onGenerateKey(_algorithm: Algorithm, extractable: boolean, _keyUsages: KeyUsage[], ..._args: any[]): Promise<CryptoKeyPair> {
        const privateKey = new CryptoKey();
        privateKey.algorithm = { name: "X25519" };
        privateKey.type = "private";
        privateKey.extractable = extractable;
        privateKey.usages = ["deriveKey", "deriveBits"];

        const publicKey = new CryptoKey();
        publicKey.algorithm = { name: "X25519" };
        publicKey.type = "public";
        publicKey.extractable = true;
        publicKey.usages = [];

        return {
          privateKey,
          publicKey,
        };
      }

      public async onDeriveKey(_algorithm: Algorithm, _baseKey: CryptoKey, _derivedKeyType: Algorithm, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
        return new CryptoKey();
      }

      public async onDeriveBits(_algorithm: Algorithm, _baseKey: CryptoKey, _length: number): Promise<ArrayBuffer> {
        return new ArrayBuffer(32);
      }
    }

    const provider = new TestX25519Provider();

    describe("generateKey", () => {
      it("should generate key pair", async () => {
        const keys = (await provider.generateKey({ name: "X25519" }, true, ["deriveKey", "deriveBits"])) as CryptoKeyPair;
        expect("privateKey" in keys).toBeTruthy();
        expect("publicKey" in keys).toBeTruthy();
        expect(keys.privateKey.algorithm.name).toBe("X25519");
        expect(keys.privateKey.type).toBe("private");
        expect(keys.privateKey.extractable).toBe(true);
        expect(keys.privateKey.usages).toStrictEqual(["deriveKey", "deriveBits"]);
        expect(keys.publicKey.algorithm.name).toBe("X25519");
        expect(keys.publicKey.type).toBe("public");
        expect(keys.publicKey.extractable).toBe(true);
        expect(keys.publicKey.usages).toStrictEqual([]);
      });
      it("should throw error when algorithm is not correct", async () => {
        await expect(provider.generateKey({ name: "RSASSA-PKCS1-v1_5" }, true, ["deriveKey", "deriveBits"])).rejects.toMatchObject({ message: "Unrecognized name" });
      });
      it("should throw error when keyUsages is not correct", async () => {
        await expect(provider.generateKey({ name: "X25519" }, true, ["encrypt", "decrypt"])).rejects.toMatchObject({ message: "Cannot create a key using the specified key usages" });
      });
    });
    describe("deriveBits", () => {
      it("should derive bits", async () => {
        const keys = (await provider.generateKey({ name: "X25519" }, true, ["deriveKey", "deriveBits"])) as CryptoKeyPair;
        expect("privateKey" in keys).toBeTruthy();
        await provider.deriveBits(
          {
            name: "X25519",
            public: keys.publicKey,
          } as EcdhKeyDeriveParams,
          keys.privateKey,
          32,
        );
      });
      it("should throw error when algorithm is not correct", async () => {
        const keys = (await provider.generateKey({ name: "X25519" }, true, ["deriveKey", "deriveBits"])) as CryptoKeyPair;
        expect("privateKey" in keys).toBeTruthy();
        await expect(provider.deriveBits({ name: "RSASSA-PKCS1-v1_5" } as EcdhKeyDeriveParams, keys.privateKey, 32)).rejects.toMatchObject({ message: "Unrecognized name" });
      });
    });
  });
});
