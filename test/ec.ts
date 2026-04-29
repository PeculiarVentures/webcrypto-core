import assert from "node:assert";
import { Convert } from "pvtsutils";
import {
  EcdhEsProvider, EcdhProvider, EcdsaProvider, EcUtils,
  EdDsaProvider, EllipticProvider, OperationError,
  CryptoKey, ProviderKeyUsages,
} from "../src";

describe("EC", () => {
  describe("EcUtils", () => {
    describe("public point", () => {
      it("encode/decode point without padding", () => {
        const point = {
          x: new Uint8Array([1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4]),
          y: new Uint8Array([5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8]),
        };
        const encoded = EcUtils.encodePoint(point, 160);

        assert.strictEqual(Convert.ToHex(encoded), "0401010101010202020202030303030304040404040505050505060606060607070707070808080808");

        const decoded = EcUtils.decodePoint(encoded, 160);
        assert.strictEqual(Convert.ToHex(decoded.x), Convert.ToHex(point.x));
        assert.strictEqual(Convert.ToHex(decoded.y), Convert.ToHex(point.y));
      });
      it("decode uncompressed point ", () => {
        const uncompressedPoint = new Uint8Array(Convert.FromHex("0400010101010202020202030303030304040404040005050505060606060607070707070808080808"));
        const decoded = EcUtils.decodePoint(uncompressedPoint, 160);
        assert.strictEqual(Convert.ToHex(decoded.x), "0001010101020202020203030303030404040404");
        assert.strictEqual(Convert.ToHex(decoded.y), "0005050505060606060607070707070808080808");
      });
    });
    describe("signature point", () => {
      it("encode/decode", () => {
        const encodedHex = "00f3e308185c2d6cb59ec216ba8ce31e0a27db431be250807e604cd858494eb9d1de066b0dc7964f64b31e2f8da7f00741b5ba7e3972fe476099d53f5c5a39905a1f009fc215304c42100a0eec7b9d0bbc5f59c838b604bcceb6ebffd4870c83e76d8eca92e689032caddc69aa87a833216163589f97ce6cb4d10c84b7d6a949e73ca1c5";
        const decoded = EcUtils.decodeSignature(Convert.FromHex(encodedHex), 521);
        assert.strictEqual(Convert.ToHex(decoded.r), "f3e308185c2d6cb59ec216ba8ce31e0a27db431be250807e604cd858494eb9d1de066b0dc7964f64b31e2f8da7f00741b5ba7e3972fe476099d53f5c5a39905a1f");
        assert.strictEqual(Convert.ToHex(decoded.s), "9fc215304c42100a0eec7b9d0bbc5f59c838b604bcceb6ebffd4870c83e76d8eca92e689032caddc69aa87a833216163589f97ce6cb4d10c84b7d6a949e73ca1c5");

        const encoded = EcUtils.encodeSignature(decoded, 521);
        assert.strictEqual(Convert.ToHex(encoded), encodedHex);
      });
    });
  });

  describe("Base", () => {
    class EcTestProvider extends EllipticProvider {
      public namedCurves = ["P-1", "P-2"];
      public name = "ECC";
      public usages: ProviderKeyUsages = {
        privateKey: ["sign"],
        publicKey: ["verify"],
      };

      public onGenerateKey(_algorithm: EcKeyGenParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
        throw new Error("Method not implemented.");
      }

      public onExportKey(_format: KeyFormat, _key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
        throw new Error("Method not implemented.");
      }

      public onImportKey(_format: KeyFormat, _keyData: JsonWebKey | ArrayBuffer, _algorithm: EcKeyImportParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
        throw new Error("Method not implemented.");
      }
    }

    const provider = new EcTestProvider();

    describe("checkGenerateKeyParams", () => {
      it("error if `namedCurve` is missing", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({} as any);
        }, Error);
      });

      it("error if `namedCurve` is not of type String", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({ namedCurve: 123 } as any);
        }, TypeError);
      });

      it("error if `namedCurve` is not value from list", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({ namedCurve: "P-256" } as any);
        }, OperationError);
      });

      it("correct `namedCurve`", () => {
        provider.checkGenerateKeyParams({ namedCurve: "P-2" } as any);
      });
    });
  });

  describe("ECDH", () => {
    const provider = Reflect.construct(EcdhProvider, []) as EcdhProvider;

    describe("", () => {
      describe("checkAlgorithmParams", () => {
        it("error if `public` is missing", () => {
          assert.throws(() => {
            provider.checkAlgorithmParams({} as any);
          }, Error);
        });

        it("error if `public` is not instance of CryptoKey", () => {
          assert.throws(() => {
            const key = {};
            provider.checkAlgorithmParams({ public: key } as any);
          }, Error);
        });

        it("error if `public` is not public CryptoKey", () => {
          assert.throws(() => {
            const key = new CryptoKey();
            key.type = "secret";
            provider.checkAlgorithmParams({ public: key } as any);
          }, Error);
        });

        it("error if `public` is wrong CryptoKey alg", () => {
          assert.throws(() => {
            const key = new CryptoKey();
            key.type = "public";
            key.algorithm = { name: "ECDSA" };
            provider.checkAlgorithmParams({ public: key } as any);
          }, Error);
        });

        it("correct `public`", () => {
          const key = new CryptoKey();
          key.type = "public";
          key.algorithm = { name: "ECDH" };
          provider.checkAlgorithmParams({ public: key } as any);
        });
      });
    });
  });

  describe("ECDSA", () => {
    const provider = Reflect.construct(EcdsaProvider, []) as EcdsaProvider;

    describe("checkAlgorithmParams", () => {
      it("error if `hash` is missing", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({} as any);
        }, Error);
      });

      it("error if `hash` has wrong value", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({ hash: { name: "wrong" } } as any);
        }, OperationError);
      });

      it("correct `hash`", () => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-1" } } as any);
      });
    });
  });

  describe("ECDH-ES", () => {
    class TestEcdhEsProvider extends EcdhEsProvider {
      public async onDeriveBits(_algorithm: EcdhKeyDeriveParams, _baseKey: CryptoKey, _length: number, ..._args: any[]): Promise<ArrayBuffer> {
        return null as any;
      }

      public async onGenerateKey(_algorithm: EcKeyGenParams, _extractable: boolean, _keyUsages: KeyUsage[], ..._args: any[]): Promise<CryptoKeyPair> {
        return null as any;
      }

      public async onExportKey(_format: KeyFormat, _key: CryptoKey, ..._args: any[]): Promise<ArrayBuffer | JsonWebKey> {
        return null as any;
      }

      public async onImportKey(_format: KeyFormat, _keyData: ArrayBuffer | JsonWebKey, _algorithm: EcKeyImportParams, _extractable: boolean, _keyUsages: KeyUsage[], ..._args: any[]): Promise<CryptoKey> {
        return null as any;
      }
    }
    const provider = new TestEcdhEsProvider();

    describe("generateKey", () => {
      ["X25519", "x448"].forEach((namedCurve) => {
        it(namedCurve, async () => {
          const keys = await provider.generateKey({
            name: "ECDH-ES", namedCurve,
          } as globalThis.EcKeyGenParams, false, ["deriveBits", "deriveKey"]);
          assert.strictEqual(keys, null);
        });
      });
    });
  });

  describe("EdDSA", () => {
    class TestEdDsaProvider extends EdDsaProvider {
      public async onSign(_algorithm: EcdsaParams, _key: CryptoKey, _data: ArrayBuffer, ..._args: any[]): Promise<ArrayBuffer> {
        return null as any;
      }

      public async onVerify(_algorithm: EcdsaParams, _key: CryptoKey, _signature: ArrayBuffer, _data: ArrayBuffer, ..._args: any[]): Promise<boolean> {
        return true;
      }

      public async onGenerateKey(_algorithm: EcKeyGenParams, _extractable: boolean, _keyUsages: KeyUsage[], ..._args: any[]): Promise<CryptoKeyPair> {
        return null as any;
      }

      public onExportKey(_format: KeyFormat, _key: CryptoKey, ..._args: any[]): Promise<ArrayBuffer | JsonWebKey> {
        return null as any;
      }

      public onImportKey(_format: KeyFormat, _keyData: ArrayBuffer | JsonWebKey, _algorithm: EcKeyImportParams, _extractable: boolean, _keyUsages: KeyUsage[], ..._args: any[]): Promise<CryptoKey> {
        return null as any;
      }
    }
    const provider = new TestEdDsaProvider();

    describe("generateKey", () => {
      ["Ed25519", "ed448"].forEach((namedCurve) => {
        it(namedCurve, async () => {
          const keys = await provider.generateKey({
            name: "EdDSA", namedCurve,
          } as globalThis.EcKeyGenParams, false, ["sign", "verify"]);
          assert.strictEqual(keys, null);
        });
      });
    });
  });
});
