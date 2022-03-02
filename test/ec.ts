import assert from "assert";
import { Convert } from "pvtsutils";
import {
  EcdhEsProvider, EcdhProvider, EcdsaProvider, EcUtils,
  EdDsaProvider, EllipticProvider, OperationError,
  CryptoKey, ProviderKeyUsages,
} from "../src";

// tslint:disable:max-classes-per-file

context("EC", () => {

  context("EcUtils", () => {
    context("public point", () => {
      it("encode/decode point without padding", () => {
        const point = {
          x: new Uint8Array([1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4]),
          y: new Uint8Array([5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8]),
        }
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
    context("signature point", () => {
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

  context("Base", () => {

    class EcTestProvider extends EllipticProvider {
      public namedCurves = ["P-1", "P-2"];
      public name = "ECC";
      public usages: ProviderKeyUsages = {
        privateKey: ["sign"],
        publicKey: ["verify"],
      };
      public onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
        throw new Error("Method not implemented.");
      }
      public onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
        throw new Error("Method not implemented.");
      }
      public onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        throw new Error("Method not implemented.");
      }
    }

    const provider = new EcTestProvider();

    context("checkGenerateKeyParams", () => {

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

  context("ECDH", () => {

    const provider = Reflect.construct(EcdhProvider, []) as EcdhProvider;

    context("", () => {

      context("checkAlgorithmParams", () => {

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

  context("ECDSA", () => {

    const provider = Reflect.construct(EcdsaProvider, []) as EcdsaProvider;

    context("checkAlgorithmParams", () => {

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

  context("ECDH-ES", () => {
    class TestEcdhEsProvider extends EcdhEsProvider {
      public async onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number, ...args: any[]): Promise<ArrayBuffer> {
        return null as any;
      }
      public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKeyPair> {
        return null as any;
      }
      public async onExportKey(format: KeyFormat, key: CryptoKey, ...args: any[]): Promise<ArrayBuffer | JsonWebKey> {
        return null as any;
      }
      public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey> {
        return null as any;
      }
    }
    const provider = new TestEcdhEsProvider();

    context("generateKey", () => {
      ["X25519", "x448"].forEach((namedCurve) => {
        it(namedCurve, async () => {
          const keys = await provider.generateKey({ name: "ECDH-ES", namedCurve } as globalThis.EcKeyGenParams, false, ["deriveBits", "deriveKey"]);
          assert.strictEqual(keys, null);
        });
      })
    });

  });

  context("EdDSA", () => {
    class TestEdDsaProvider extends EdDsaProvider {
      public async onSign(algorithm: EcdsaParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer> {
        return null as any;
      }
      public async onVerify(algorithm: EcdsaParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean> {
        return true;
      }
      public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKeyPair> {
        return null as any;
      }
      public onExportKey(format: KeyFormat, key: CryptoKey, ...args: any[]): Promise<ArrayBuffer | JsonWebKey> {
        return null as any;
      }
      public onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey> {
        return null as any;
      }
    }
    const provider = new TestEdDsaProvider();

    context("generateKey", () => {
      ["Ed25519", "ed448"].forEach((namedCurve) => {
        it(namedCurve, async () => {
          const keys = await provider.generateKey({ name: "EdDSA", namedCurve } as globalThis.EcKeyGenParams, false, ["sign", "verify"]);
          assert.strictEqual(keys, null);
        });
      })
    });

  });

});
