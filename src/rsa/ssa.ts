import { ProviderKeyUsages } from "../types";
import { RsaProvider } from "./base";

export type RsaSsaParams = Algorithm;

export abstract class RsaSsaProvider extends RsaProvider {
  public readonly name = "RSASSA-PKCS1-v1_5";

  public usages: ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };

  public abstract override onSign(algorithm: RsaSsaParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onVerify(algorithm: RsaSsaParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean>;
}
