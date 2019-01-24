import assert from "assert";
import { AesCbcProvider, AesCmacProvider, AesCtrProvider, AesGcmProvider, AesProvider } from "../src/aes";
import { AlgorithmError, OperationError } from "../src/errors";

context("AES", () => {

  context("AES-CBC", () => {

    const provider = new AesCbcProvider();

    context("checkGenerateKey", () => {

      context("algorithm", () => {

        it("error if `name` is wrong", () => {
          assert.throws(() => {
            provider.checkGenerateKey({ name: "AES-WRONG", length: 128 }, false, ["encrypt"]);
          }, AlgorithmError);
        });

        it("lower case `name`", () => {
          provider.checkGenerateKey({ name: "aes-cbc", length: 128 }, false, ["encrypt"]);
        });

        it("error if `length` is not present", () => {
          assert.throws(() => {
            provider.checkGenerateKey({ name: "AES-CBC" } as any, false, ["encrypt"]);
          }, Error);
        });

        it("error if `length` has wrong type", () => {
          assert.throws(() => {
            provider.checkGenerateKey({ name: "AES-CBC", length: "s" } as any, false, ["encrypt"]);
          }, TypeError);
        });

        it("error if `length` has wrong value", () => {
          assert.throws(() => {
            provider.checkGenerateKey({ name: "AES-CBC", length: 1 } as any, false, ["encrypt"]);
          }, TypeError);
        });

        [128, 192, 256].forEach((length) => {
          it(`correct length:${length}`, () => {
            provider.checkGenerateKey({ name: "AES-CBC", length } as any, false, ["encrypt"]);
          });
        });

      });

      context("key usages", () => {

      });
    });

  });

  context("AES-CBC", () => {

    const provider = new AesCbcProvider();

    context("checkAlgorithmParams", () => {

      it("error if parameter `iv` is not present", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({} as any);
        }, Error);
      });

      it("error if parameter `iv` has wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            iv: "wrong type",
          } as any);
        }, TypeError);
      });

      it("error if parameter `iv` has wrong length", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            iv: new Uint8Array(20),
          } as any);
        }, TypeError);
      });

      it("correct parameter `iv`", () => {
        provider.checkAlgorithmParams({
          iv: new Uint8Array(16),
        } as any);
      });

    });

  });

  context("AES-CMAC", () => {

    const provider = new AesCmacProvider();

    context("checkAlgorithmParams", () => {

      it("error if parameter `length` is not present", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({} as any);
        }, Error);
      });

      it("error if parameter `length` has wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            length: "128",
          } as any);
        }, TypeError);
      });

      it("error if parameter `length` less than 1", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            length: 0,
          } as any);
        }, OperationError);
      });

      it("correct parameter `length`", () => {
        provider.checkAlgorithmParams({
          length: 1,
        } as any);
      });

    });

  });

  context("AES-CTR", () => {

    const provider = new AesCtrProvider();

    context("checkAlgorithmParams", () => {

      it("error if parameter `counter` is not present", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            length: 1,
          } as any);
        }, Error);
      });

      it("error if parameter `counter` has wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            counter: "wrong type",
            length: 1,
          } as any);
        }, TypeError);
      });

      it("error if parameter `counter` has wrong length", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            counter: new ArrayBuffer(10),
            length: 1,
          } as any);
        }, TypeError);
      });

      it("counter is ArrayBuffer", () => {
        provider.checkAlgorithmParams({
          counter: new ArrayBuffer(16),
          length: 1,
        } as any);
      });

      it("counter is ArrayBufferView", () => {
        provider.checkAlgorithmParams({
          counter: new Uint8Array(16),
          length: 1,
        } as any);
      });

      it("error if parameter `length` is not present", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            counter: new Uint8Array(16),
          } as any);
        }, Error);
      });

      it("error if parameter `length` has wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            counter: new Uint8Array(16),
            length: "1",
          } as any);
        }, TypeError);
      });

      it("error if parameter `length` less than 1", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            counter: new Uint8Array(16),
            length: 0,
          } as any);
        }, OperationError);
      });

      it("correct parameter `length`", () => {
        provider.checkAlgorithmParams({
          counter: new Uint8Array(16),
          length: 1,
        } as any);
      });

    });

  });

  context("AES-GCM", () => {

    const provider = new AesGcmProvider();

    context("checkAlgorithmParams", () => {

      it("error if parameter `iv` is not present", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({} as any);
        }, Error);
      });

      it("error if parameter `iv` has wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            iv: "wrong type",
          } as any);
        }, TypeError);
      });

      it("error if parameter `iv` has wrong length", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            iv: new Uint8Array(0),
          } as any);
        }, OperationError);
      });

      it("correct parameter `iv`", () => {
        provider.checkAlgorithmParams({
          iv: new ArrayBuffer(1),
        } as any);
      });

      it("error if parameter `tagLength` has wrong value", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            iv: new ArrayBuffer(1),
            tagLength: 33,
          } as any);
        }, OperationError);
      });

      [32, 64, 96, 104, 112, 120, 128].forEach((tagLength) => {
        it(`correct tagLength: ${tagLength}`, () => {
          provider.checkAlgorithmParams({
            iv: new ArrayBuffer(1),
            tagLength,
          } as any);
        });
      });

    });

  });

});
