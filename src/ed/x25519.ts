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
  public override getDeriveBitsLength(_algorithm: Algorithm, _baseKey: globalThis.CryptoKey, length: number | null, _options?: IProviderCheckOptions): number | null {
    return length === null ? 256 : length;
  }

  public abstract override onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number | null): Promise<ArrayBuffer>;
}
