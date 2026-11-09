import { OperationError } from "../errors";
import { CryptoKey } from "../crypto_key";
import type { ProviderKeyUsages } from "../types";
import { EllipticProvider } from "./base";
import { EcCurves } from "./curves";
import type { IProviderCheckOptions } from "../provider";

export abstract class EcdhProvider extends EllipticProvider {
  public readonly name: string = "ECDH";

  public usages: ProviderKeyUsages = {
    privateKey: ["deriveBits", "deriveKey"],
    publicKey: [],
  };

  public namedCurves = ["P-256", "P-384", "P-521", "K-256"];

  public override checkAlgorithmParams(algorithm: EcdhKeyDeriveParams): void {
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

  /**
   * Resolves full-secret requests to byte-rounded sizes from EcCurves, including 528 bits for P-521.
   * Unregistered curves retain the legacy 512-bit internal deriveKey request, or null for direct calls.
   * Register curve metadata or override this hook to provide exact sizing for a custom curve.
   */
  public override getDeriveBitsLength(_algorithm: Algorithm, baseKey: globalThis.CryptoKey, length: number | null, options: IProviderCheckOptions = {}): number | null {
    if (length === null) {
      const namedCurve = (baseKey.algorithm as EcKeyAlgorithm).namedCurve;
      const curve = typeof namedCurve === "string" ? EcCurves.find(namedCurve) : null;
      if (curve) {
        return Math.ceil(curve.size / 8) * 8;
      }
      return super.getDeriveBitsLength(_algorithm, baseKey, length, options);
    }
    return length;
  }

  public abstract override onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number | null, ...args: any[]): Promise<ArrayBuffer>;
}
