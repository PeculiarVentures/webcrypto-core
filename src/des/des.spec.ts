import { describe, it, expect } from "vitest";
import { CryptoKey, DesProvider, OperationError } from "../index";

class DesTestProvider extends DesProvider {
  public keySizeBits = 64;
  public ivSize = 8;
  public name = "DES-TEST";

  public onGenerateKey(_algorithm: import("./index").DesKeyGenParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }

  public onExportKey(_format: KeyFormat, _key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    throw new Error("Method not implemented.");
  }

  public onImportKey(_format: KeyFormat, _keyData: JsonWebKey | ArrayBuffer, _algorithm: import("./index").DesImportParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }

  public onEncrypt(_algorithm: import("./index").DesParams, _key: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }

  public onDecrypt(_algorithm: import("./index").DesParams, _key: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
}

describe("DES", () => {
  const provider = new DesTestProvider();

  describe("checkAlgorithmParams", () => {
    it("error if `iv` is not present", () => {
      expect(() => {
        provider.checkAlgorithmParams({} as any);
      }).toThrow(Error);
    });

    it("error if `iv` has wrong type", () => {
      expect(() => {
        provider.checkAlgorithmParams({ iv: "wrong type" } as any);
      }).toThrow(TypeError);
    });

    it("error if `iv` has wrong length", () => {
      expect(() => {
        provider.checkAlgorithmParams({ iv: new ArrayBuffer(9) } as any);
      }).toThrow(TypeError);
    });

    it("correct `iv` length", () => {
      provider.checkAlgorithmParams({ iv: new Uint8Array(8) } as any);
    });
  });

  describe("checkGenerateKeyParams", () => {
    it("error if `length` is not present", () => {
      expect(() => {
        provider.checkGenerateKeyParams({} as any);
      }).toThrow(Error);
    });

    it("error if `length` has wrong type", () => {
      expect(() => {
        provider.checkGenerateKeyParams({ length: "8" } as any);
      }).toThrow(TypeError);
    });

    it("error if `length` has wrong value", () => {
      expect(() => {
        provider.checkGenerateKeyParams({ length: 8 } as any);
      }).toThrow(OperationError);
    });

    it("correct value", () => {
      provider.checkGenerateKeyParams({ length: 64 } as any);
    });
  });
});
