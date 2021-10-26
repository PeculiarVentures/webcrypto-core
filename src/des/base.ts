import { OperationError } from "../errors";
import { KeyAlgorithm, CryptoKey } from "../crypto_key";
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

export interface DesDerivedKeyParams extends Algorithm {
  length: number;
}

export interface DesImportParams extends Algorithm { }

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

  public checkGenerateKeyParams(algorithm: DesKeyGenParams) {
    // length
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not of type Number");
    }
    if (algorithm.length !== this.keySizeBits) {
      throw new OperationError(`algorithm.length: Must be ${this.keySizeBits}`);
    }
  }

  public checkDerivedKeyParams(algorithm: DesDerivedKeyParams) {
    this.checkGenerateKeyParams(algorithm);
  }

  public abstract onGenerateKey(algorithm: DesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract onExportKey(format: KeyFormat, key: CryptoKey, ...args: any[]): Promise<JsonWebKey | ArrayBuffer>;
  public abstract onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: DesImportParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract onEncrypt(algorithm: DesParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract onDecrypt(algorithm: DesParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
