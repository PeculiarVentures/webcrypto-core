import { ProviderKeyUsages } from "../types";
import { RsaProvider } from "./base";

export abstract class RsaPssProvider extends RsaProvider {

  public readonly name = "RSA-PSS";

  public usages: ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };

  public checkAlgorithmParams(algorithm: RsaPssParams): void {
    this.checkRequiredProperty(algorithm, "saltLength");
    if (typeof algorithm.saltLength !== "number") {
      throw new TypeError("saltLength: Is not a Number");
    }
    if (algorithm.saltLength < 0) {
      throw new RangeError("saltLength: Must be positive number");
    }
  }

  public abstract onSign(algorithm: RsaPssParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract onVerify(algorithm: RsaPssParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean>;

}
