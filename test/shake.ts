import assert from "assert";
import { CryptoKey, DesProvider, OperationError, ProviderKeyUsages, Shake128Provider, Shake256Provider, ShakeParams } from "../src";

class TestShake128Provider extends Shake128Provider {
  public async onDigest(algorithm: Required<ShakeParams>, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new ArrayBuffer(algorithm.length);
  }
}

// tslint:disable-next-line: max-classes-per-file
class TestShake256Provider extends Shake256Provider {
  public async onDigest(algorithm: Required<ShakeParams>, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new ArrayBuffer(algorithm.length);
  }
}

context("SHAKE", () => {

  const data = new Uint8Array();
  const shake128 = new TestShake128Provider();
  const shake256 = new TestShake256Provider();

  context("check parameters", () => {

    context("algorithm.length", () => {
      it("negative value", async () => {
        assert.rejects(shake128.digest({ name: "Shake128", length: -1 } as Algorithm, data), TypeError);
      });

      it("wrong type", async () => {
        assert.rejects(shake128.digest({ name: "Shake128", length: "wrong" } as Algorithm, data), TypeError);
      });
    });

  });

  context("shake128", () => {

    it("default length", async () => {
      const digest = await shake128.digest({ name: "shake128" }, data);
      assert.strictEqual(digest.byteLength, 16);
    });

  });

  context("shake256", () => {

    it("default length", async () => {
      const digest = await shake256.digest({ name: "Shake256" }, data);
      assert.strictEqual(digest.byteLength, 32);
    });

  });

});
