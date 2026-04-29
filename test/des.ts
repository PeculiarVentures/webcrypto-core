import assert from "assert";
import {
  CryptoKey, DesProvider, OperationError,
} from "../src";

class DesTestProvider extends DesProvider {
  public keySizeBits = 64;
  public ivSize = 8;
  public name = "DES-TEST";

  public onGenerateKey(_algorithm: import("../src/des").DesKeyGenParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }

  public onExportKey(_format: KeyFormat, _key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    throw new Error("Method not implemented.");
  }

  public onImportKey(_format: KeyFormat, _keyData: JsonWebKey | ArrayBuffer, _algorithm: import("../src/des").DesImportParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }

  public onEncrypt(_algorithm: import("../src/des").DesParams, _key: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }

  public onDecrypt(_algorithm: import("../src/des").DesParams, _key: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
}

describe("DES", () => {
  const provider = new DesTestProvider();

  describe("checkAlgorithmParams", () => {
    it("error if `iv` is not present", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({} as any);
      }, Error);
    });

    it("error if `iv` has wrong type", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ iv: "wrong type" } as any);
      }, TypeError);
    });

    it("error if `iv` has wrong length", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ iv: new ArrayBuffer(9) } as any);
      }, TypeError);
    });

    it("correct `iv` length", () => {
      provider.checkAlgorithmParams({ iv: new Uint8Array(8) } as any);
    });
  });

  describe("checkGenerateKeyParams", () => {
    it("error if `length` is not present", () => {
      assert.throws(() => {
        provider.checkGenerateKeyParams({} as any);
      }, Error);
    });

    it("error if `length` has wrong type", () => {
      assert.throws(() => {
        provider.checkGenerateKeyParams({ length: "8" } as any);
      }, TypeError);
    });

    it("error if `length` has wrong value", () => {
      assert.throws(() => {
        provider.checkGenerateKeyParams({ length: 8 } as any);
      }, OperationError);
    });

    it("correct value", () => {
      provider.checkGenerateKeyParams({ length: 64 } as any);
    });
  });
});
