import { OperationError } from "../errors";
import { ProviderCrypto } from "../provider";

export abstract class EllipticProvider extends ProviderCrypto {

  public abstract namedCurves: string[];

  public checkGenerateKeyParams(algorithm: EcKeyGenParams) {
    // named curve
    this.checkRequiredProperty(algorithm, "namedCurve");
    this.checkNamedCurve(algorithm.namedCurve);
  }

  public checkNamedCurve(namedCurve: string) {
    for (const item of this.namedCurves) {
      if (item.toLowerCase() === namedCurve.toLowerCase()) {
        return;
      }
    }
    throw new OperationError(`namedCurve: Must be one of ${this.namedCurves.join(", ")}`);
  }

}
