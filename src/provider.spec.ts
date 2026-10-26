import { describe, it, expect } from "vitest";
import type { ProviderKeyPairUsage } from "./index";
import { AlgorithmError, CryptoError, OperationError, UnsupportedOperationError } from "./errors";
import { CryptoKey } from "./crypto_key";
import { ProviderCrypto } from "./provider";

class TestProvider extends ProviderCrypto {
  public name = "CUSTOM-ALG";
  public usages: KeyUsage[] = ["sign"];
}

class TestAsymmetricProvider extends ProviderCrypto {
  public name = "CUSTOM-ALG";
  public usages: ProviderKeyPairUsage = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };
}

describe("ProviderCrypto", () => {
  const crypto = new TestProvider();

  describe("checkGenerateKey", () => {
    it("error if `keyUsages` argument is empty list", () => {
      expect(() => {
        crypto.checkGenerateKey({ name: "CUSTOM-ALG" }, true, []);
      }).toThrow(TypeError);
    });

    it("check usages for symmetric key", () => {
      const aProv = new TestAsymmetricProvider();
      aProv.checkGenerateKey({ name: "CUSTOM-ALG" }, true, ["sign", "verify"]);
    });
  });

  describe("digest", () => {
    it("correct data", async () => {
      await expect(crypto.digest({ name: "custom-alg" }, new ArrayBuffer(0))).rejects.toThrow(UnsupportedOperationError);
    });

    it("wrong name of algorithm", async () => {
      await expect(crypto.digest({ name: "wrong" }, new ArrayBuffer(0))).rejects.toThrow();
    });
  });

  describe("generateKey", () => {
    it("correct data", async () => {
      await expect(crypto.generateKey({ name: "custom-alg" }, true, ["sign"])).rejects.toThrow(UnsupportedOperationError);
    });

    it("wrong name of algorithm", async () => {
      await expect(crypto.generateKey({ name: "wrong" }, false, ["sign"])).rejects.toThrow();
    });

    it("wrong key usages", async () => {
      await expect(crypto.generateKey({ name: "custom-alg" }, false, ["verify"])).rejects.toThrow();
    });
  });

  describe("sign", () => {
    const correctKey = CryptoKey.create({ name: "custom-alg" }, "secret", false, ["sign"]);

    it("correct data", async () => {
      await expect(crypto.sign({ name: "custom-alg" }, correctKey, new ArrayBuffer(0))).rejects.toThrow(UnsupportedOperationError);
    });

    it("wrong name of algorithm", async () => {
      await expect(crypto.sign({ name: "wrong" }, correctKey, new ArrayBuffer(0))).rejects.toThrow();
    });

    it("wrong key type", async () => {
      await expect(crypto.sign({ name: "custom-alg" }, {} as CryptoKey, new ArrayBuffer(0))).rejects.toThrow(TypeError);
    });

    it("wrong key algorithm", async () => {
      await expect(crypto.sign({ name: "custom-alg" }, CryptoKey.create({ name: "wrong" }, "secret", true, ["sign", "decrypt"]), new ArrayBuffer(0))).rejects.toThrow(AlgorithmError);
    });

    it("wrong key usage", async () => {
      await expect(crypto.sign({ name: "custom-alg" }, CryptoKey.create({ name: "custom-alg" }, "secret", true, ["verify"]), new ArrayBuffer(0))).rejects.toThrow(CryptoError);
    });
  });

  describe("checkDeriveBits", () => {
    it("error if length is not multiple 8", () => {
      const algorithm: Algorithm = { name: "custom-alg" };
      const key = CryptoKey.create(algorithm, "secret", false, ["deriveBits"]);
      expect(() => {
        crypto.checkDeriveBits(algorithm, key, 7);
      }).toThrow(OperationError);
    });
  });

  describe("checkKeyFormat", () => {
    it("error if wrong value", () => {
      expect(() => {
        crypto.checkKeyFormat("wrong");
      }).toThrow(TypeError);
    });
  });
});
