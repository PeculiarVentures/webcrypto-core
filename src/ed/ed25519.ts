import { ProviderCrypto } from "../provider";
import { ProviderKeyUsages } from "../types";

export abstract class Ed25519Provider extends ProviderCrypto {

  public readonly name: string = "Ed25519";

  public usages: ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };

  public abstract onSign(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract onVerify(algorithm: Algorithm, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean>;
}