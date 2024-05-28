import { ProviderCrypto } from "../provider";
import { ProviderKeyUsages } from "../types";

export abstract class X25519Provider extends ProviderCrypto {

  public readonly name: string = "X25519";

  public usages: ProviderKeyUsages = {
    privateKey: ["deriveKey", "deriveBits"],
    publicKey: [],
  };

  public checkAlgorithmParams(algorithm: EcdhKeyDeriveParams): void {
    this.checkRequiredProperty(algorithm, "public");
  }

  public abstract onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): Promise<ArrayBuffer>;
}
