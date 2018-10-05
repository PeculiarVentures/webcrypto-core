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

    public static checkKey(key: CryptoKey, alg?: string, type: string | null = null, usage: string | null = null) {
        // check key empty
        if (!key) {
            throw new CryptoKeyError(CryptoKeyError.EMPTY_KEY);
        }
        // check type
        if (type && (!key.type || key.type.toUpperCase() !== type.toUpperCase())) {
            throw new CryptoKeyError(CryptoKeyError.WRONG_KEY_TYPE, key.type, type);
        }
        // check usage
        if (usage) {
            if (!key.usages.some((keyUsage) => usage.toUpperCase() === keyUsage.toUpperCase())) {
                throw new CryptoKeyError(CryptoKeyError.WRONG_KEY_USAGE, usage);
            }
        }
    }
}

interface ChaCha20KeyGenParams {
    length: number;
}
