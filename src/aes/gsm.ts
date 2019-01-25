import { OperationError } from "../errors";
import { KeyUsages } from "../types";
import { AesProvider } from "./base";

export class AesGcmProvider extends AesProvider {

  public readonly name = "AES-GCM";

  public usages: KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  public checkAlgorithmParams(algorithm: AesGcmParams) {
    // iv
    this.checkRequiredProperty(algorithm, "iv");
    if (!(algorithm.iv instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.iv))) {
      throw new TypeError("iv: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
    if (algorithm.iv.byteLength < 1) {
      throw new OperationError("iv: Must have length more than 0 and less than 2^64 - 1");
    }
    // tagLength
    if (!("tagLength" in algorithm)) {
      algorithm.tagLength = 128;
    }
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

}
