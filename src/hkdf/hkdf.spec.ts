import { describe, it, expect } from "vitest";
import { HkdfProvider, OperationError } from "../index";

describe("HKDF", () => {
  const provider = Reflect.construct(HkdfProvider, []) as HkdfProvider;

  describe("checkAlgorithmParams", () => {
    it("error if `hash` is missing", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          salt: new Uint8Array(4),
          info: new Uint8Array(4),
        } as any);
      }).toThrow(Error);
    });

    it("error if `hash` is wrong", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "WRONG" },
          salt: new Uint8Array(4),
          info: new Uint8Array(4),
        } as any);
      }).toThrow(OperationError);
    });

    it("error if `salt` is missing", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "SHA-256" },
          info: new Uint8Array(4),
        } as any);
      }).toThrow(Error);
    });

    it("error if `salt` wrong type", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "SHA-256" },
          salt: "wrong",
          info: new Uint8Array(4),
        } as any);
      }).toThrow(TypeError);
    });

    it("error if `info` is missing", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "SHA-256" },
          salt: new Uint8Array(4),
        } as any);
      }).toThrow(Error);
    });

    it("error if `info` wrong type", () => {
      expect(() => {
        provider.checkAlgorithmParams({
          hash: { name: "SHA-256" },
          info: "wrong",
          salt: new Uint8Array(4),
        } as any);
      }).toThrow(TypeError);
    });

    it("correct value", () => {
      provider.checkAlgorithmParams({
        hash: { name: "SHA-256" },
        salt: new Uint8Array(4),
        info: new Uint8Array(4),
      } as any);
    });
  });

  describe("checkImportKey", () => {
    it("throw error if extractable is true", () => {
      expect(() => {
        provider.checkImportKey("raw", new ArrayBuffer(0), { name: "HKDF" }, true, ["deriveBits"]);
      }).toThrow(SyntaxError);
    });

    it("correct extractable value", () => {
      provider.checkImportKey("raw", new ArrayBuffer(0), { name: "HKDF" }, false, ["deriveBits"]);
    });
  });
});
