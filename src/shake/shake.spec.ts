import { describe, it, expect } from "vitest";
import { toArrayBuffer } from "@peculiar/utils/bytes";
import type { ShakeParams } from "../index";
import { Shake128Provider, Shake256Provider } from "../index";

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
        await expect(
          shake128.digest(
            {
              name: "Shake128",
              length: -1,
            } as Algorithm,
            toArrayBuffer(data),
          ),
        ).rejects.toThrow(TypeError);
      });

      it("wrong type", async () => {
        await expect(
          shake128.digest(
            {
              name: "Shake128",
              length: "wrong",
            } as Algorithm,
            toArrayBuffer(data),
          ),
        ).rejects.toThrow(TypeError);
      });
    });
  });

  describe("shake128", () => {
    it("default length", async () => {
      const digest = await shake128.digest({ name: "shake128" }, toArrayBuffer(data));
      expect(digest.byteLength).toBe(16);
    });
  });

  describe("shake256", () => {
    it("default length", async () => {
      const digest = await shake256.digest({ name: "Shake256" }, toArrayBuffer(data));
      expect(digest.byteLength).toBe(32);
    });
  });
});
