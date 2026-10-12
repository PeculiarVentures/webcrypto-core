import { describe, it, expect } from "vitest";
import { OperationError } from "../errors";
import { HmacProvider } from "./index";

describe("HMAC", () => {
  const provider = Reflect.construct(HmacProvider, []) as HmacProvider;

  describe("checkGenerateKeyParams", () => {
    it("error if `hash` is missing", () => {
      expect(() => {
        provider.checkGenerateKeyParams({} as any);
      }).toThrow(Error);
    });

    it("error if `hash` is wrong", () => {
      expect(() => {
        provider.checkGenerateKeyParams({ hash: { name: "WRONG" } } as any);
      }).toThrow(OperationError);
    });

    it("error if `length` is not of type Number", () => {
      expect(() => {
        provider.checkGenerateKeyParams({
          hash: { name: "SHA-256" },
          length: "128",
        } as any);
      }).toThrow(TypeError);
    });

    it("error if `length` is less than 1", () => {
      expect(() => {
        provider.checkGenerateKeyParams({
          hash: { name: "SHA-256" },
          length: 0,
        } as any);
      }).toThrow(RangeError);
    });

    it("default length", () => {
      provider.checkGenerateKeyParams({ hash: { name: "SHA-256" } } as any);
    });

    it("custom length", () => {
      provider.checkGenerateKeyParams({
        hash: {
          name: "SHA-256",
          length: 128,
        },
      } as any);
    });
  });

  describe("getDefaultLength", () => {
    it("SHA-1", () => {
      const len = provider.getDefaultLength("SHA-1");
      expect(len).toBe(512);
    });

    it("SHA-256", () => {
      const len = provider.getDefaultLength("SHA-256");
      expect(len).toBe(512);
    });

    it("SHA-384", () => {
      const len = provider.getDefaultLength("SHA-384");
      expect(len).toBe(512);
    });

    it("SHA-512", () => {
      const len = provider.getDefaultLength("SHA-512");
      expect(len).toBe(512);
    });

    it("error if unknown name", () => {
      expect(() => {
        provider.getDefaultLength("SHA-521");
      }).toThrow(Error);
    });
  });

  describe("checkImportParams", () => {
    it("error if `hash` is missing", () => {
      expect(() => {
        provider.checkImportParams({} as any);
      }).toThrow(Error);
    });

    it("error if `hash` is wrong", () => {
      expect(() => {
        provider.checkImportParams({ hash: { name: "WRONG" } } as any);
      }).toThrow(OperationError);
    });
  });
});
