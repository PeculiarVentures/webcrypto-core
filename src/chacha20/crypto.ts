import { AlgorithmNames } from "../alg";
import { BaseCrypto } from "../base";
import { AlgorithmError, CryptoKeyError, WebCryptoError } from "../error";

export class ChaCha20 extends BaseCrypto {
    public static ALG_NAME = "ChaCha20";
    public static KEY_USAGES: string[] = [ "encrypt", "decrypt" ];

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

    public static checkKeyGenParams(alg: AesKeyGenParams) {
        if (alg.length !== 256) {
            throw new AlgorithmError(AlgorithmError.PARAM_WRONG_VALUE, "length", "128, 192 or 256");
        }
    }
}
