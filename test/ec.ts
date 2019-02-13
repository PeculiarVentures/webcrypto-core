import assert from "assert";
import { EcdhProvider, EcdsaProvider, EddsaProvider, EllipticProvider } from "../src/ec";
import { OperationError } from "../src/errors";
import { CryptoKey } from "../src/key";
import { ProviderKeyUsages } from "../src/types";

context("EC", () => {

  context("Base", () => {

    class EcTestProvider extends EllipticProvider {
      public namedCurves = ["P-1", "P-2"];
      public name = "ECC";
      public usages: ProviderKeyUsages = {
        privateKey: ["sign"],
        publicKey: ["verify"],
      };
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

    const provider = new EcdhProvider();

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

    const provider = new EcdsaProvider();

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

  context("EDDSA", () => {
    const provider = new EddsaProvider();

    it("error if bad namedCurve", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({name: "EDDSA", namedCurve: "P-256"});
      });
    });

    it("correct namedCurve", () => {
      provider.checkAlgorithmParams({name: "EDDSA", namedCurve: "ED25519"});
    });

  });

});
