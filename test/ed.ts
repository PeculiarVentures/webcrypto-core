import { AsnConvert, AsnSerializer } from "@peculiar/asn1-schema";
import * as assert from "assert";
import { Convert } from "pvtsutils";
import { EdPrivateKey, EdPublicKey, OneAsymmetricKey, PublicKeyInfo } from "../src/asn1";
import { CryptoKey, Ed25519Provider, X25519Provider } from "../src";

context("ED", () => {

  context("asn", () => {

    it("spki - jwk", () => {
      const pem = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

      const keyInfo = AsnConvert.parse(Convert.FromBase64(pem), PublicKeyInfo);
      const key = new EdPublicKey(keyInfo.publicKey);
      const jwk = key.toJSON();

      const key2 = new EdPublicKey();
      key2.fromJSON(jwk);
      assert.strictEqual(
        Convert.ToBase64(AsnSerializer.serialize(key2)),
        Convert.ToBase64(AsnSerializer.serialize(key)),
      );
    });

    context("pkcs8 -jwk", () => {

      it("without public key", () => {
        const pem = "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";

        const keyInfo = AsnConvert.parse(Convert.FromBase64(pem), OneAsymmetricKey);
        assert.strictEqual(keyInfo.publicKey, undefined);
        const key = AsnConvert.parse(keyInfo.privateKey, EdPrivateKey);
        const jwk = key.toJSON();

        const key2 = new EdPrivateKey();
        key2.fromJSON(jwk);
        assert.strictEqual(
          Convert.ToBase64(AsnSerializer.serialize(key2)),
          Convert.ToBase64(AsnSerializer.serialize(key)),
        );
      });

      it("with public key", () => {
        const pem = "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhCoB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

        const keyInfo = AsnConvert.parse(Convert.FromBase64(pem), OneAsymmetricKey);
        assert.ok(keyInfo.publicKey);
        const key = AsnConvert.parse(keyInfo.privateKey, EdPrivateKey);
        const jwk = key.toJSON();

        const key2 = new EdPrivateKey();
        key2.fromJSON(jwk);
        assert.strictEqual(
          Convert.ToBase64(AsnSerializer.serialize(key2)),
          Convert.ToBase64(AsnSerializer.serialize(key)),
        );
      });

    });

  });

  context("Ed25519", () => {
    class TestEd25519Provider extends Ed25519Provider {
      public override async onGenerateKey(algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], ..._args: any[]): Promise<CryptoKeyPair> {
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

      public async onSign(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer> {
        return new ArrayBuffer(64);
      }
      public async onVerify(algorithm: Algorithm, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean> {
        return true;
      }
    }

    const provider = new TestEd25519Provider();

    context("generateKey", () => {
      it("should generate key pair", async () => {
        const keys = await provider.generateKey({
          name: "Ed25519",
        }, true, ["sign", "verify"]);
        assert.ok("privateKey" in keys);
        assert.ok("publicKey" in keys);
        assert.strictEqual(keys.privateKey.algorithm.name, "Ed25519");
        assert.strictEqual(keys.privateKey.type, "private");
        assert.strictEqual(keys.privateKey.extractable, true);
        assert.deepStrictEqual(keys.privateKey.usages, ["sign"]);
        assert.strictEqual(keys.publicKey.algorithm.name, "Ed25519");
        assert.strictEqual(keys.publicKey.type, "public");
        assert.strictEqual(keys.publicKey.extractable, true);
        assert.deepStrictEqual(keys.publicKey.usages, ["verify"]);
      });
      it("should throw error when algorithm is not correct", async () => {
        await assert.rejects(provider.generateKey({
          name: "RSASSA-PKCS1-v1_5",
        }, true, ["sign", "verify"]), {
          message: "Unrecognized name",
        });
      });
      it("should throw error when keyUsages is not correct", async () => {
        await assert.rejects(provider.generateKey({
          name: "Ed25519",
        }, true, ["encrypt", "decrypt"]), {
          message: "Cannot create a key using the specified key usages",
        });
      });
    });
    context("sign", () => {
      it("should sign data", async () => {
        const keys = await provider.generateKey({
          name: "Ed25519",
        }, true, ["sign", "verify"]);
        assert.ok("privateKey" in keys);
        const signature = await provider.sign({
          name: "Ed25519",
        }, keys.privateKey, new ArrayBuffer(32));
      });
      it("should throw error when algorithm is not correct", async () => {
        const keys = await provider.generateKey({
          name: "Ed25519",
        }, true, ["sign", "verify"]);
        assert.ok("privateKey" in keys);
        await assert.rejects(provider.sign({
          name: "RSASSA-PKCS1-v1_5",
        }, keys.privateKey, new ArrayBuffer(32)), {
          message: "Unrecognized name",
        });
      });
    });
    context("verify", () => {
      it("should verify signature", async () => {
        const keys = await provider.generateKey({
          name: "Ed25519",
        }, true, ["sign", "verify"]);
        assert.ok("privateKey" in keys);
        const signature = new ArrayBuffer(64);
        const res = await provider.verify({
          name: "Ed25519",
        }, keys.publicKey, signature, new ArrayBuffer(32));
        assert.strictEqual(res, true);
      });
      it("should throw error when algorithm is not correct", async () => {
        const keys = await provider.generateKey({
          name: "Ed25519",
        }, true, ["sign", "verify"]);
        assert.ok("privateKey" in keys);
        const signature = new ArrayBuffer(64);
        await assert.rejects(provider.verify({
          name: "RSASSA-PKCS1-v1_5",
        }, keys.publicKey, signature, new ArrayBuffer(32)), {
          message: "Unrecognized name",
        });
      });
    });
  });
  context("X25519", () => {
    class TestX25519Provider extends X25519Provider {
      public override async onGenerateKey(algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], ..._args: any[]): Promise<CryptoKeyPair> {
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

      public async onDeriveKey(algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        return new CryptoKey();
      }
      public async onDeriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
        return new ArrayBuffer(32);
      }
    }

    const provider = new TestX25519Provider();

    context("generateKey", () => {
      it("should generate key pair", async () => {
        const keys = await provider.generateKey({
          name: "X25519",
        }, true, ["deriveKey", "deriveBits"]);
        assert.ok("privateKey" in keys);
        assert.ok("publicKey" in keys);
        assert.strictEqual(keys.privateKey.algorithm.name, "X25519");
        assert.strictEqual(keys.privateKey.type, "private");
        assert.strictEqual(keys.privateKey.extractable, true);
        assert.deepStrictEqual(keys.privateKey.usages, ["deriveKey", "deriveBits"]);
        assert.strictEqual(keys.publicKey.algorithm.name, "X25519");
        assert.strictEqual(keys.publicKey.type, "public");
        assert.strictEqual(keys.publicKey.extractable, true);
        assert.deepStrictEqual(keys.publicKey.usages, []);
      });
      it("should throw error when algorithm is not correct", async () => {
        await assert.rejects(provider.generateKey({
          name: "RSASSA-PKCS1-v1_5",
        }, true, ["deriveKey", "deriveBits"]), {
          message: "Unrecognized name",
        });
      });
      it("should throw error when keyUsages is not correct", async () => {
        await assert.rejects(provider.generateKey({
          name: "X25519",
        }, true, ["encrypt", "decrypt"]), {
          message: "Cannot create a key using the specified key usages",
        });
      });
    });
    context("deriveBits", () => {
      it("should derive bits", async () => {
        const keys = await provider.generateKey({
          name: "X25519",
        }, true, ["deriveKey", "deriveBits"]);
        assert.ok("privateKey" in keys);
        const bits = await provider.deriveBits({
          name: "X25519",
          public: keys.publicKey,
        } as EcdhKeyDeriveParams, keys.privateKey, 32);
      });
      it("should throw error when algorithm is not correct", async () => {
        const keys = await provider.generateKey({
          name: "X25519",
        }, true, ["deriveKey", "deriveBits"]);
        assert.ok("privateKey" in keys);
        await assert.rejects(provider.deriveBits({
          name: "RSASSA-PKCS1-v1_5",
        } as EcdhKeyDeriveParams, keys.privateKey, 32), {
          message: "Unrecognized name",
        });
      });
    });
  });
});
