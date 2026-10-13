import { describe, it, expect } from "vitest";
import { CryptoKey } from "./crypto_key";

describe("CryptoKey", () => {
  describe("isKeyType", () => {
    it("correct key type", () => {
      expect(CryptoKey.isKeyType("secret")).toBe(true);
    });
    it("incorrect key type", () => {
      expect(CryptoKey.isKeyType("Secret")).toBe(false);
    });
  });
});
