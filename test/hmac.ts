import assert from "assert";
import { OperationError } from "../src/errors";
import { HmacProvider } from "../src/hmac";

describe("HMAC", () => {
  const provider = Reflect.construct(HmacProvider, []) as HmacProvider;

  describe("checkGenerateKeyParams", () => {
    it("error if `hash` is missing", () => {
      assert.throws(() => {
        provider.checkGenerateKeyParams({} as any);
      }, Error);
    });

    it("error if `hash` is wrong", () => {
      assert.throws(() => {
        provider.checkGenerateKeyParams({ hash: { name: "WRONG" } } as any);
      }, OperationError);
    });

    it("error if `length` is not of type Number", () => {
      assert.throws(() => {
        provider.checkGenerateKeyParams({
          hash: { name: "SHA-256" }, length: "128",
        } as any);
      }, TypeError);
    });

    it("error if `length` is less than 1", () => {
      assert.throws(() => {
        provider.checkGenerateKeyParams({
          hash: { name: "SHA-256" }, length: 0,
        } as any);
      }, RangeError);
    });

    it("default length", () => {
      provider.checkGenerateKeyParams({ hash: { name: "SHA-256" } } as any);
    });

    it("custom length", () => {
      provider.checkGenerateKeyParams({
        hash: {
          name: "SHA-256", length: 128,
        },
      } as any);
    });
  });

  describe("getDefaultLength", () => {
    it("SHA-1", () => {
      const len = provider.getDefaultLength("SHA-1");
      assert.equal(len, 512);
    });

    it("SHA-256", () => {
      const len = provider.getDefaultLength("SHA-256");
      assert.equal(len, 512);
    });

    it("SHA-384", () => {
      const len = provider.getDefaultLength("SHA-384");
      assert.equal(len, 512);
    });

    it("SHA-512", () => {
      const len = provider.getDefaultLength("SHA-512");
      assert.equal(len, 512);
    });

    it("error if unknown name", () => {
      assert.throws(() => {
        provider.getDefaultLength("SHA-521");
      }, Error);
    });
  });

  describe("checkImportParams", () => {
    it("error if `hash` is missing", () => {
      assert.throws(() => {
        provider.checkImportParams({} as any);
      }, Error);
    });

    it("error if `hash` is wrong", () => {
      assert.throws(() => {
        provider.checkImportParams({ hash: { name: "WRONG" } } as any);
      }, OperationError);
    });
  });
});
