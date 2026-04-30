import assert from "node:assert";
import { toArrayBuffer } from "@peculiar/utils/bytes";
import {
  Shake128Provider, Shake256Provider, ShakeParams,
} from "../src";

class TestShake128Provider extends Shake128Provider {
  public async onDigest(algorithm: Required<ShakeParams>, _data: ArrayBuffer): Promise<ArrayBuffer> {
    return new ArrayBuffer(algorithm.length);
  }
}

class TestShake256Provider extends Shake256Provider {
  public async onDigest(algorithm: Required<ShakeParams>, _data: ArrayBuffer): Promise<ArrayBuffer> {
    return new ArrayBuffer(algorithm.length);
  }
}

describe("SHAKE", () => {
  const data = new Uint8Array();
  const shake128 = new TestShake128Provider();
  const shake256 = new TestShake256Provider();

  describe("check parameters", () => {
    describe("algorithm.length", () => {
      it("negative value", async () => {
        assert.rejects(shake128.digest({
          name: "Shake128", length: -1,
        } as Algorithm, toArrayBuffer(data)), TypeError);
      });

      it("wrong type", async () => {
        assert.rejects(shake128.digest({
          name: "Shake128", length: "wrong",
        } as Algorithm, toArrayBuffer(data)), TypeError);
      });
    });
  });

  describe("shake128", () => {
    it("default length", async () => {
      const digest = await shake128.digest({ name: "shake128" }, toArrayBuffer(data));
      assert.strictEqual(digest.byteLength, 16);
    });
  });

  describe("shake256", () => {
    it("default length", async () => {
      const digest = await shake256.digest({ name: "Shake256" }, toArrayBuffer(data));
      assert.strictEqual(digest.byteLength, 32);
    });
  });
});
