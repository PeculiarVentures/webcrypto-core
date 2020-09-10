import { ProviderKeyUsages } from "../types";
import { RsaProvider } from "./base";

export abstract class RsaOaepProvider extends RsaProvider {

  public readonly name = "RSA-OAEP";

  public usages: ProviderKeyUsages = {
    privateKey: ["decrypt", "unwrapKey"],
    publicKey: ["encrypt", "wrapKey"],
  };

  public checkAlgorithmParams(algorithm: RsaOaepParams) {
    // label
    if (algorithm.label
      && !(algorithm.label instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.label))) {
      throw new TypeError("label: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
  }

  public abstract onEncrypt(algorithm: RsaOaepParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract onDecrypt(algorithm: RsaOaepParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
