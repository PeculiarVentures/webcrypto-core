import { describe, it, expect } from "vitest";
import { RsaOaepProvider, RsaPssProvider, RsaSsaProvider } from "../index";

describe("RSA", () => {
  describe("RSASSA-PKCS1-v1_5", () => {
    const provider = Reflect.construct(RsaSsaProvider, []) as RsaSsaProvider;

    describe("checkGenerateKeyParams", () => {
      it("error if `hash` is missing", () => {
        expect(() => {
          provider.checkGenerateKeyParams({
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
          } as any);
        }).toThrow(Error);
      });

      it("error if `hash` is wrong", () => {
        expect(() => {
          provider.checkGenerateKeyParams({
            hash: { name: "SHA-WRONG" },
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
          } as any);
        }).toThrow(Error);
      });

      it("error if `publicExponent` is missing", () => {
        expect(() => {
          provider.checkGenerateKeyParams({
            hash: { name: "SHA-256" },
            modulusLength: 2048,
          } as any);
        }).toThrow(Error);
      });

      it("error if `publicExponent` is wrong of type", () => {
        expect(() => {
          provider.checkGenerateKeyParams({
            hash: { name: "SHA-256" },
            publicExponent: [1, 0, 1],
            modulusLength: 2048,
          } as any);
        }).toThrow(TypeError);
      });

      it("error if `publicExponent` is value", () => {
        expect(() => {
          provider.checkGenerateKeyParams({
            hash: { name: "SHA-256" },
            publicExponent: new Uint8Array([1, 1, 0]),
            modulusLength: 2048,
          } as any);
        }).toThrow(TypeError);
      });

      it("error if `modulusLength` is missing", () => {
        expect(() => {
          provider.checkGenerateKeyParams({
            hash: { name: "SHA-256" },
            publicExponent: new Uint8Array([1, 0, 1]),
          } as any);
        }).toThrow(Error);
      });

      describe("error if `modulusLength` is wrong value", () => {
        it("not multiple of 8 bits", () => {
          expect(() => {
            provider.checkGenerateKeyParams({
              hash: { name: "SHA-256" },
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 12345,
            } as any);
          }).toThrow(TypeError);
        });
        it("less than 256", () => {
          expect(() => {
            provider.checkGenerateKeyParams({
              hash: { name: "SHA-256" },
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 256 - 8,
            } as any);
          }).toThrow(TypeError);
        });
        it("more than 16384", () => {
          expect(() => {
            provider.checkGenerateKeyParams({
              hash: { name: "SHA-256" },
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 16384 + 8,
            } as any);
          }).toThrow(TypeError);
        });
      });

      it("correct value", () => {
        provider.checkGenerateKeyParams({
          hash: { name: "SHA-256" },
          publicExponent: new Uint8Array([1, 0, 1]),
          modulusLength: 4096,
        } as any);
      });
    });

    describe("checkImportParams", () => {
      it("error if `hash` is missing", () => {
        expect(() => {
          provider.checkImportParams({
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
          } as any);
        }).toThrow(Error);
      });

      it("error if `hash` is wrong", () => {
        expect(() => {
          provider.checkImportParams({
            hash: { name: "SHA-WRONG" },
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
          } as any);
        }).toThrow(Error);
      });
    });
  });

  describe("RSA-OAEP", () => {
    const provider = Reflect.construct(RsaOaepProvider, []) as RsaOaepProvider;

    describe("checkAlgorithmParams", () => {
      it("error if `label` is wrong type", () => {
        expect(() => {
          provider.checkAlgorithmParams({ label: "WRONG" } as any);
        }).toThrow(TypeError);
      });

      it("correct `label`", () => {
        provider.checkAlgorithmParams({ label: new Uint8Array(4) } as any);
      });
    });
  });

  describe("RSA-PSS", () => {
    const provider = Reflect.construct(RsaPssProvider, []) as RsaPssProvider;

    describe("checkAlgorithmParams", () => {
      it("error if `saltLength` is missing", () => {
        expect(() => {
          provider.checkAlgorithmParams({} as any);
        }).toThrow(Error);
      });

      it("error if `saltLength` is not of type Number", () => {
        expect(() => {
          provider.checkAlgorithmParams({ saltLength: "123" } as any);
        }).toThrow(TypeError);
      });

      it("error if `saltLength` is less than 0", () => {
        expect(() => {
          provider.checkAlgorithmParams({ saltLength: -1 } as any);
        }).toThrow(RangeError);
      });

      it("correct `saltLength`", () => {
        provider.checkAlgorithmParams({ saltLength: 8 } as any);
      });
    });
  });
});
