import { KeyUsages } from "../types";
import { AesProvider } from "./base";

export abstract class AesCbcProvider extends AesProvider {

  public readonly name = "AES-CBC";

  public usages: KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  public checkAlgorithmParams(algorithm: AesCbcParams) {
    this.checkRequiredProperty(algorithm, "iv");
    if (!(algorithm.iv instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.iv))) {
      throw new TypeError("iv: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
    if (algorithm.iv.byteLength !== 16) {
      throw new TypeError("iv: Must have length 16 bytes");
    }
  }

  public abstract onEncrypt(algorithm: AesCbcParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract onDecrypt(algorithm: AesCbcParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
