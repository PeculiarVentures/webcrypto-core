import { ProviderKeyUsages } from "../types";
import { RsaProvider } from "./base";

export interface RsaSsaParams extends Algorithm { }

export abstract class RsaSsaProvider extends RsaProvider {

  public readonly name = "RSASSA-PKCS1-v1_5";

  public usages: ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };

  public abstract onSign(algorithm: RsaSsaParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer>;
  public abstract onVerify(algorithm: RsaSsaParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean>;

}
