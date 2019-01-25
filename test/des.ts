import assert from "assert";
import { DesProvider } from "../src/des";
import { OperationError } from "../src/errors";

class DesTestProvider extends DesProvider {

  public keySizeBits = 64;
  public ivSize = 8;
  public name = "DES-TEST";

}

context("DES", () => {

  const provider = new DesTestProvider();

  context("checkAlgorithmParams", () => {

    it("error if `iv` is not present", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({
        } as any);
      }, Error);
    });

    it("error if `iv` has wrong type", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({
          iv: "wrong type",
        } as any);
      }, TypeError);
    });

    it("error if `iv` has wrong length", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({
          iv: new ArrayBuffer(9),
        } as any);
      }, TypeError);
    });

    it("correct `iv` length", () => {
      provider.checkAlgorithmParams({
        iv: new Uint8Array(8),
      } as any);
    });

  });

  context("checkGenerateKeyParams", () => {

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
