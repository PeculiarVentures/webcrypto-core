import { describe, it, expect } from "vitest";
import { AesCbcProvider, AesCmacProvider, AesCtrProvider, AesGcmProvider } from "./index";
import { OperationError } from "../errors";

describe("AES", () => {
  describe("AES-CBC", () => {
    const provider = Reflect.construct(AesCbcProvider, []) as AesCbcProvider;

    describe("checkGenerateKeyParams", () => {
      it("error if `length` is not present", () => {
        expect(() => {
          provider.checkGenerateKeyParams({ name: "AES-CBC" } as any);
        }).toThrow(Error);
      });

      it("error if `length` has wrong type", () => {
        expect(() => {
          provider.checkGenerateKeyParams({
            name: "AES-CBC",
            length: "s",
          } as any);
        }).toThrow(TypeError);
      });

      it("error if `length` has wrong value", () => {
        expect(() => {
          provider.checkGenerateKeyParams({
            name: "AES-CBC",
            length: 1,
          } as any);
        }).toThrow(TypeError);
      });

      [128, 192, 256].forEach((length) => {
        it(`correct length:${length}`, () => {
          provider.checkGenerateKeyParams({
            name: "AES-CBC",
            length,
          } as any);
        });
      });
    });
  });

  describe("AES-CBC", () => {
    const provider = Reflect.construct(AesCbcProvider, []) as AesCbcProvider;

    describe("checkAlgorithmParams", () => {
      it("error if parameter `iv` is not present", () => {
        expect(() => {
          provider.checkAlgorithmParams({} as any);
        }).toThrow(Error);
      });

      it("error if parameter `iv` has wrong type", () => {
        expect(() => {
          provider.checkAlgorithmParams({ iv: "wrong type" } as any);
        }).toThrow(TypeError);
      });

      it("error if parameter `iv` has wrong length", () => {
        expect(() => {
          provider.checkAlgorithmParams({ iv: new Uint8Array(20) } as any);
        }).toThrow(TypeError);
      });

      it("correct parameter `iv`", () => {
        provider.checkAlgorithmParams({ iv: new Uint8Array(16) } as any);
      });
    });
  });

  describe("AES-CMAC", () => {
    const provider = Reflect.construct(AesCmacProvider, []) as AesCmacProvider;

    describe("checkAlgorithmParams", () => {
      it("error if parameter `length` is not present", () => {
        expect(() => {
          provider.checkAlgorithmParams({} as any);
        }).toThrow(Error);
      });

      it("error if parameter `length` has wrong type", () => {
        expect(() => {
          provider.checkAlgorithmParams({ length: "128" } as any);
        }).toThrow(TypeError);
      });

      it("error if parameter `length` less than 1", () => {
        expect(() => {
          provider.checkAlgorithmParams({ length: 0 } as any);
        }).toThrow(OperationError);
      });

      it("correct parameter `length`", () => {
        provider.checkAlgorithmParams({ length: 1 } as any);
      });
    });
  });

  describe("AES-CTR", () => {
    const provider = Reflect.construct(AesCtrProvider, []) as AesCtrProvider;

    describe("checkAlgorithmParams", () => {
      it("error if parameter `counter` is not present", () => {
        expect(() => {
          provider.checkAlgorithmParams({ length: 1 } as any);
        }).toThrow(Error);
      });

      it("error if parameter `counter` has wrong type", () => {
        expect(() => {
          provider.checkAlgorithmParams({
            counter: "wrong type",
            length: 1,
          } as any);
        }).toThrow(TypeError);
      });

      it("error if parameter `counter` has wrong length", () => {
        expect(() => {
          provider.checkAlgorithmParams({
            counter: new ArrayBuffer(10),
            length: 1,
          } as any);
        }).toThrow(TypeError);
      });

      it("counter is ArrayBuffer", () => {
        provider.checkAlgorithmParams({
          counter: new ArrayBuffer(16),
          length: 1,
        } as any);
      });

      it("counter is ArrayBufferView", () => {
        provider.checkAlgorithmParams({
          counter: new Uint8Array(16),
          length: 1,
        } as any);
      });

      it("error if parameter `length` is not present", () => {
        expect(() => {
          provider.checkAlgorithmParams({ counter: new Uint8Array(16) } as any);
        }).toThrow(Error);
      });

      it("error if parameter `length` has wrong type", () => {
        expect(() => {
          provider.checkAlgorithmParams({
            counter: new Uint8Array(16),
            length: "1",
          } as any);
        }).toThrow(TypeError);
      });

      it("error if parameter `length` less than 1", () => {
        expect(() => {
          provider.checkAlgorithmParams({
            counter: new Uint8Array(16),
            length: 0,
          } as any);
        }).toThrow(OperationError);
      });

      it("correct parameter `length`", () => {
        provider.checkAlgorithmParams({
          counter: new Uint8Array(16),
          length: 1,
        } as any);
      });
    });
  });

  describe("AES-GCM", () => {
    const provider = Reflect.construct(AesGcmProvider, []) as AesGcmProvider;

    describe("checkAlgorithmParams", () => {
      it("error if parameter `iv` is not present", () => {
        expect(() => {
          provider.checkAlgorithmParams({} as any);
        }).toThrow(Error);
      });

      it("error if parameter `iv` has wrong type", () => {
        expect(() => {
          provider.checkAlgorithmParams({ iv: "wrong type" } as any);
        }).toThrow(TypeError);
      });

      it("error if parameter `iv` has wrong length", () => {
        expect(() => {
          provider.checkAlgorithmParams({ iv: new Uint8Array(0) } as any);
        }).toThrow(OperationError);
      });

      it("correct parameter `iv`", () => {
        provider.checkAlgorithmParams({ iv: new ArrayBuffer(1) } as any);
      });

      it("error if parameter `tagLength` has wrong value", () => {
        expect(() => {
          provider.checkAlgorithmParams({
            iv: new ArrayBuffer(1),
            tagLength: 33,
          } as any);
        }).toThrow(OperationError);
      });

      [32, 64, 96, 104, 112, 120, 128].forEach((tagLength) => {
        it(`correct tagLength: ${tagLength}`, () => {
          provider.checkAlgorithmParams({
            iv: new ArrayBuffer(1),
            tagLength,
          } as any);
        });
      });
    });
  });
});
