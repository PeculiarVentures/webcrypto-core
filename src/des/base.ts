import { OperationError } from "../errors";
import { KeyAlgorithm } from "../key";
import { ProviderCrypto } from "../provider";
import { KeyUsages } from "../types";

export interface DesKeyAlgorithm extends KeyAlgorithm {
  length: number;
}

export interface DesParams extends Algorithm {
  iv: BufferSource;
}

export interface DesKeyGenParams extends Algorithm {
  length: number;
}

export abstract class DesProvider extends ProviderCrypto {

  public usages: KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  public abstract keySizeBits: number;
  public abstract ivSize: number;

  public checkAlgorithmParams(algorithm: AesCbcParams) {
    if (this.ivSize) {
      this.checkRequiredProperty(algorithm, "iv");
      if (!(algorithm.iv instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.iv))) {
        throw new TypeError("iv: Is not of type '(ArrayBuffer or ArrayBufferView)'");
      }
      if (algorithm.iv.byteLength !== this.ivSize) {
        throw new TypeError(`iv: Must have length ${this.ivSize} bytes`);
      }
    }
  }

  public checkImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsages) {
    super.checkImportKey(format, keyData, algorithm, extractable, keyUsages)
    this.checkKeyUsages(keyUsages, this.usages);
  }

  public checkGenerateKey(algorithm: DesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]) {
    super.checkGenerateKey(algorithm, extractable, keyUsages);

    // length
    this.checkRequiredProperty(algorithm, "length");
    if (algorithm.length !== this.keySizeBits) {
      throw new OperationError(`algorith.length: Must be ${this.keySizeBits}`);
    }
  }

}
