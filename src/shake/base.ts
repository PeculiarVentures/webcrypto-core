import { Convert } from "pvtsutils";
import { ProviderCrypto } from "../provider";
import { ProviderKeyUsages } from "../types";

export interface ShakeParams extends Algorithm {
  /**
   * Output length in bytes
   */
  length?: number;
}

export abstract class ShakeProvider extends ProviderCrypto {

  public usages = [];
  public defaultLength = 0;

  public override digest(algorithm: Algorithm, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public override digest(...args: any[]): Promise<ArrayBuffer> {
    args[0] = { length: this.defaultLength, ...args[0] };

    return super.digest.apply(this, args);
  }

  public override checkDigest(algorithm: ShakeParams, data: ArrayBuffer): void {
    super.checkDigest(algorithm, data);

    const length = algorithm.length || 0;
    if (typeof length !== "number") {
      throw new TypeError("length: Is not a Number");
    }
    if (length < 0) {
      throw new TypeError("length: Is negative");
    }
  }

  public abstract onDigest(algorithm: Required<ShakeParams>, data: ArrayBuffer): Promise<ArrayBuffer>;

}
