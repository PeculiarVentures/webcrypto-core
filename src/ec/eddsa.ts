import { ProviderKeyUsages } from "../types";
import { EllipticProvider } from "./base";

export class EddsaProvider extends EllipticProvider {

  public readonly name = "EDDSA";

  public readonly namedCurves = ["ED25519", "ED25519PH", "ED448", "ED25519CTX", "ED448PH"];

  public usages: ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };

  public checkAlgorithmParams(algorithm: EcKeyAlgorithm) {
    this.checkNamedCurve(algorithm.namedCurve);
  }
}
