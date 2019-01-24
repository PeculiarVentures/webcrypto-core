import assert from "assert";
import { AlgorithmError, CryptoError, UnsupportedOperationError } from "../src/errors";
import { CryptoKey } from "../src/key";
import { ProviderCrypto } from "../src/provider";

class TestProvider extends ProviderCrypto {
  public name = "CUSTOM-ALG";
  public usages: KeyUsage[] = ["sign"];
}

context("ProviderCrypto", () => {

  const crypto = new TestProvider();

  context("digest", () => {

    it("correct data", async () => {
      await assert.rejects(
        crypto.digest({ name: "custom-alg" }, new ArrayBuffer(0)),
        UnsupportedOperationError,
      );
    });

    it("wrong name of algorithm", async () => {
      await assert.rejects(
        crypto.digest({ name: "wrong" }, new ArrayBuffer(0)),
      );
    });

  });

  context("generateKey", () => {

    it("correct data", async () => {
      await assert.rejects(
        crypto.generateKey({ name: "custom-alg" }, true, ["sign"]),
        UnsupportedOperationError,
      );
    });

    it("wrong name of algorithm", async () => {
      await assert.rejects(
        crypto.generateKey({ name: "wrong" }, false, ["sign"]),
      );
    });

    it("wrong key usages", async () => {
      await assert.rejects(
        crypto.generateKey({ name: "custom-alg" }, false, ["verify"]),
      );
    });

  });

  context("sign", () => {

    const correctKey = CryptoKey.create(
      { name: "custom-alg" },
      "secret",
      false,
      ["sign"],
    );

    it("correct data", async () => {
      await assert.rejects(
        crypto.sign(
          { name: "custom-alg" },
          correctKey,
          new ArrayBuffer(0),
        ),
        UnsupportedOperationError,
      );
    });

    it("wrong name of algorithm", async () => {
      await assert.rejects(
        crypto.sign(
          { name: "wrong" },
          correctKey,
          new ArrayBuffer(0),
        ),
      );
    });

    it("wrong key type", async () => {
      await assert.rejects(
        crypto.sign(
          { name: "custom-alg" },
          {} as CryptoKey,
          new ArrayBuffer(0),
        ),
        TypeError,
      );
    });

    it("wrong key algorithm", async () => {
      await assert.rejects(
        crypto.sign(
          { name: "custom-alg" },
          CryptoKey.create(
            { name: "wrong" },
            "secret",
            true,
            ["sign", "decrypt"],
          ),
          new ArrayBuffer(0),
        ),
        AlgorithmError,
      );
    });

    it("wrong key usage", async () => {
      await assert.rejects(
        crypto.sign(
          { name: "custom-alg" },
          CryptoKey.create(
            { name: "custom-alg" },
            "secret",
            true,
            ["verify"],
          ),
          new ArrayBuffer(0),
        ),
        CryptoError,
      );
    });

  });

});
