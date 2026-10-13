import { describe, it, expect } from "vitest";
import { OperationError, Pbkdf2Provider } from "../index";

describe("HMAC", () => {
  const provider = Reflect.construct(Pbkdf2Provider, []) as Pbkdf2Provider;

  describe("checkAlgorithmParams", () => {
    it("error if `hash` is missing", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          salt: new Uint8Array(4),
          iterations: 1000,
        } as any);
      }).toThrow(Error);
    });

    it("error if `hash` is wrong", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "WRONG" },
          salt: new Uint8Array(4),
          iterations: 1000,
        } as any);
      }).toThrow(OperationError);
    });

    it("error if `salt` is missing", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "SHA-256" },
          iterations: 1000,
        } as any);
      }).toThrow(Error);
    });

    it("error if `salt` wrong type", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "SHA-256" },
          salt: "wrong",
          iterations: 1000,
        } as any);
      }).toThrow(TypeError);
    });

    it("error if `iterations` is missing", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "SHA-256" },
          salt: new Uint8Array(4),
        } as any);
      }).toThrow(Error);
    });

    it("error if `iterations` wrong type", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "SHA-256" },
          salt: new Uint8Array(4),
          iterations: "123",
        } as any);
      }).toThrow(TypeError);
    });

    it("error if `iterations` less than 1", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "SHA-256" },
          salt: new Uint8Array(4),
          iterations: 0,
        } as any);
      }).toThrow(TypeError);
    });

    it("correct value", () => {
      provider.checkAlgorithmParams({
        hash: { name: "SHA-256" },
        salt: new Uint8Array(4),
        iterations: 1000,
      } as any);
    });
  });

  describe("checkImportKey", () => {
    it("throw error if extractable is true", () => {
      expect(() => {
        provider.checkImportKey("raw", new ArrayBuffer(0), { name: "PBKDF2" }, true, ["deriveBits"]);
      }).toThrow(SyntaxError);
    });

    it("correct extractable value", () => {
      provider.checkImportKey("raw", new ArrayBuffer(0), { name: "PBKDF2" }, false, ["deriveBits"]);
    });
  });
});
