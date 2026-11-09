import { ProviderCrypto, type IProviderCheckOptions } from "../provider";
import type { ProviderKeyUsages } from "../types";

export abstract class X25519Provider extends ProviderCrypto {
  public readonly name: string = "X25519";

  public usages: ProviderKeyUsages = {
    privateKey: ["deriveKey", "deriveBits"],
    publicKey: [],
  };

  public override checkAlgorithmParams(algorithm: EcdhKeyDeriveParams): void {
    this.checkRequiredProperty(algorithm, "public");
  }

  /** Requests the full 256-bit secret for null, including from existing numeric-only backends. */
  public override async deriveBits(algorithm: Algorithm, baseKey: globalThis.CryptoKey, length: number | null, options?: IProviderCheckOptions, ...args: any[]): Promise<ArrayBuffer> {
    return super.deriveBits(algorithm, baseKey, length === null ? 256 : length, options, ...args);
  }

  public abstract override onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number | null): Promise<ArrayBuffer>;
}
