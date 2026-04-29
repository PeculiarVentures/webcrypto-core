import assert from "node:assert";
import { CryptoKey } from "../src/crypto_key";

describe("CryptoKey", () => {
  describe("isKeyType", () => {
    it("correct key type", () => {
      assert.equal(CryptoKey.isKeyType("secret"), true);
    });
    it("incorrect key type", () => {
      assert.equal(CryptoKey.isKeyType("Secret"), false);
    });
  });
});
