import { OperationError } from "../errors";
import { CryptoKey } from "../key";
import { ProviderKeyUsages } from "../types";
import { EllipticProvider } from "./base";

export abstract class EcdhProvider extends EllipticProvider {

  public readonly name = "ECDH";

  public usages: ProviderKeyUsages = {
    privateKey: ["deriveBits", "deriveKey"],
    publicKey: [],
  };

  public namedCurves = ["P-256", "P-384", "P-521", "K-256"];

  public checkAlgorithmParams(algorithm: EcdhKeyDeriveParams) {
    // public
    this.checkRequiredProperty(algorithm, "public");
    if (!(algorithm.public instanceof CryptoKey)) {
      throw new TypeError("public: Is not a CryptoKey");
    }
    if (algorithm.public.type !== "public") {
      throw new OperationError("public: Is not a public key");
    }
    if (algorithm.public.algorithm.name !== this.name) {
      throw new OperationError(`public: Is not ${this.name} key`);
    }
  }

  public abstract onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): Promise<ArrayBuffer>;

}
