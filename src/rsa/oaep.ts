import { ProviderKeyUsages } from "../types";
import { RsaProvider } from "./base";

export class RsaOaepProvider extends RsaProvider {

  public readonly name = "RSA-OAEP";

  public usages: ProviderKeyUsages = {
    privateKey: ["decrypt", "unwrapKey"],
    publicKey: ["encrypt", "wrapKey"],
  };

  public checkAlgorithmParams(algorithm: RsaOaepParams) {
    if (algorithm.label
      && !(algorithm.label instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.label))) {
      throw new TypeError("label: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
  }

}
