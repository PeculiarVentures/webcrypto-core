import { OperationError } from "../errors";
import { KeyUsages } from "../types";
import { AesProvider } from "./base";

export interface AesCmacParams extends Algorithm {
  length: number;
}

export abstract class AesCmacProvider extends AesProvider {

  public readonly name = "AES-CMAC";

  public usages: KeyUsages = ["sign", "verify"];

  public checkAlgorithmParams(algorithm: AesCmacParams) {
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not a Number");
    }
    if (algorithm.length < 1) {
      throw new OperationError("length: Must be more than 0");
    }
  }

  public abstract onSign(algorithm: AesCmacParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract onVerify(algorithm: AesCmacParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean>;

}
