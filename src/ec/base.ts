import { OperationError } from "../errors";
import { ProviderCrypto } from "../provider";

export abstract class EllipticProvider extends ProviderCrypto {

  public abstract namedCurves: string[];

  public checkGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]) {
    super.checkGenerateKey.apply(this, arguments);

    // check key gen params
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
