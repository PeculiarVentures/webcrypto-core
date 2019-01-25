import { ProviderKeyUsages } from "../types";
import { RsaProvider } from "./base";

export class RsaPssProvider extends RsaProvider {

  public readonly name = "RSA-PSS";

  public usages: ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };

  public checkAlgorithmParams(algorithm: RsaPssParams) {
    this.checkRequiredProperty(algorithm, "saltLength");
    if (typeof algorithm.saltLength !== "number") {
      throw new TypeError("saltLength: Is not a Number");
    }
    if (algorithm.saltLength < 1) {
      throw new RangeError("saltLength: Must be more than 0");
    }
  }

}
