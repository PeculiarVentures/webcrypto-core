import { AlgorithmNames } from "../alg";
import { BaseCrypto } from "../base";
import { AlgorithmError, CryptoKeyError, WebCryptoError } from "../error";

export interface DesKeyGenParams extends Algorithm {
    length: number;
}

export interface DesCbcParams extends Algorithm {
  iv: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer;
}

export interface DesEdeCbcParams extends Algorithm {
  iv: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer;
}

export interface DesKeyDeriveParams extends Algorithm {
    length: number;
}

export class Des extends BaseCrypto {

    public static ALG_NAME = "";
    public static KEY_LENGTH = 64;
    public static KEY_USAGES: string[] = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

    public static checkKeyUsages(keyUsages: string[]) {
        super.checkKeyUsages(keyUsages);
        const wrongUsage = keyUsages.filter((usage) => this.KEY_USAGES.indexOf(usage) === -1);
        if (wrongUsage.length) {
            throw new AlgorithmError(AlgorithmError.WRONG_USAGE, wrongUsage.join(", "));
        }
    }

    public static checkAlgorithm(alg: Algorithm) {
        if (alg.name.toUpperCase() !== this.ALG_NAME.toUpperCase()) {
            throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg.name, this.ALG_NAME);
        }
    }

    public static checkKeyGenParams(alg: DesKeyGenParams) {
      if (!("length" in alg)) {
        throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, "length");
      }
      if (typeof alg.length !== "number") {
        throw new AlgorithmError(AlgorithmError.PARAM_WRONG_TYPE, "length", "Number");
      }
      if (alg.length !== this.KEY_LENGTH) {
        throw new AlgorithmError(AlgorithmError.PARAM_WRONG_VALUE, "length", `${this.KEY_LENGTH}`);
      }
    }

    public static generateKey(algorithm: DesKeyGenParams, extractable: boolean, keyUsages: string[]): Promise<CryptoKey | CryptoKeyPair> {
        return new Promise((resolve) => {
            this.checkAlgorithm(algorithm);
            this.checkKeyGenParams(algorithm);
            this.checkKeyUsages(keyUsages);
            resolve(undefined);
        });
    }

    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkKey(key, this.ALG_NAME);
            this.checkFormat(format, key.type);
            resolve(undefined);
        });
    }
    public static importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve) => {
            this.checkAlgorithm(algorithm);
            this.checkFormat(format);
            if (!(format.toLowerCase() === "raw" || format.toLowerCase() === "jwk")) {
                throw new CryptoKeyError(CryptoKeyError.ALLOWED_FORMAT, format, "'jwk' or 'raw'");
            }
            this.checkKeyUsages(keyUsages);
            resolve(undefined);
        });
    }

    public static wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm): PromiseLike<ArrayBuffer> {
      return new Promise((resolve, reject) => {
          this.checkAlgorithmParams(wrapAlgorithm);
          this.checkKey(wrappingKey, this.ALG_NAME, "secret", "wrapKey");
          this.checkWrappedKey(key);
          this.checkFormat(format, key.type);
          resolve(undefined);
      });
  }

  public static unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
      return new Promise((resolve, reject) => {
          this.checkAlgorithmParams(unwrapAlgorithm);
          this.checkKey(unwrappingKey, this.ALG_NAME, "secret", "unwrapKey");
          this.checkFormat(format);
          // TODO check unwrappedKeyAlgorithm
          // TODO check keyUSages
          resolve(undefined);
      });
  }

    public static encrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
      return new Promise((resolve, reject) => {
          this.checkAlgorithmParams(algorithm);
          this.checkKey(key, this.ALG_NAME, "secret", "encrypt");
          resolve(undefined);
      });
  }

  public static decrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
      return new Promise((resolve, reject) => {
          this.checkAlgorithmParams(algorithm);
          this.checkKey(key, this.ALG_NAME, "secret", "decrypt");
          resolve(undefined);
      });
  }
}

export class DesCBC extends Des {

    public static ALG_NAME = AlgorithmNames.DesCBC;

    public static checkAlgorithmParams(alg: DesCbcParams) {
        this.checkAlgorithm(alg);
        if (!alg.iv) {
            throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, "iv");
        }
        if (!(ArrayBuffer.isView(alg.iv) || alg.iv instanceof ArrayBuffer)) {
            throw new AlgorithmError(AlgorithmError.PARAM_WRONG_TYPE, "iv", "ArrayBufferView or ArrayBuffer");
        }
        if (alg.iv.byteLength !== 8) {
            throw new AlgorithmError(AlgorithmError.PARAM_WRONG_VALUE, "iv", "ArrayBufferView or ArrayBuffer with size 8");
        }
    }

}

export class DesEdeCBC extends DesCBC {

    public static ALG_NAME = AlgorithmNames.DesEdeCBC;
    public static KEY_LENGTH = 192;

}
