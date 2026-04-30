import { ProviderKeyUsages } from "../types";
import { RsaProvider } from "./base";

export abstract class RsaPssProvider extends RsaProvider {
  public readonly name = "RSA-PSS";

  public usages: ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };

  public override checkAlgorithmParams(algorithm: RsaPssParams): void {
    this.checkRequiredProperty(algorithm, "saltLength");
    if (typeof algorithm.saltLength !== "number") {
      throw new TypeError("saltLength: Is not a Number");
    }
    if (algorithm.saltLength < 0) {
      throw new RangeError("saltLength: Must be positive number");
    }
  }

  public abstract override onSign(algorithm: RsaPssParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onVerify(algorithm: RsaPssParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean>;
}
