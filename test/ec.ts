import assert from "assert";
import "reflect-metadata";
import { EcdhEsProvider, EcdhProvider, EcdsaProvider, EdDsaProvider, EllipticProvider } from "../src/ec";
import { OperationError } from "../src/errors";
import { CryptoKey } from "../src/key";
import { ProviderKeyUsages } from "../src/types";

// tslint:disable:max-classes-per-file

context("EC", () => {

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
      public async onExportKey(format: KeyFormat, key: globalThis.CryptoKey, ...args: any[]): Promise<ArrayBuffer | JsonWebKey> {
        return null as any;
      }
      public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<globalThis.CryptoKey> {
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
      public async onSign(algorithm: EcdsaParams, key: globalThis.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer> {
        return null as any;
      }
      public async onVerify(algorithm: EcdsaParams, key: globalThis.CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean> {
        return true;
      }
      public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKeyPair> {
        return null as any;
      }
      public onExportKey(format: KeyFormat, key: globalThis.CryptoKey, ...args: any[]): Promise<ArrayBuffer | JsonWebKey> {
        return null as any;
      }
      public onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<globalThis.CryptoKey> {
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
