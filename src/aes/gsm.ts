import { OperationError } from "../errors";
import { KeyUsages } from "../types";
import { AesProvider } from "./base";

export abstract class AesGcmProvider extends AesProvider {

  public readonly name = "AES-GCM";

  public usages: KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  public checkAlgorithmParams(algorithm: AesGcmParams): void {
    // iv
    this.checkRequiredProperty(algorithm, "iv");
    if (!(algorithm.iv instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.iv))) {
      throw new TypeError("iv: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
    if (algorithm.iv.byteLength < 1) {
      throw new OperationError("iv: Must have length more than 0 and less than 2^64 - 1");
    }
    // tagLength
    algorithm.tagLength ??= 128;    

    switch (algorithm.tagLength) {
      case 32:
      case 64:
      case 96:
      case 104:
      case 112:
      case 120:
      case 128:
        break;
      default:
        throw new OperationError("tagLength: Must be one of 32, 64, 96, 104, 112, 120 or 128");
    }
  }

  public abstract onEncrypt(algorithm: AesGcmParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract onDecrypt(algorithm: AesGcmParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
