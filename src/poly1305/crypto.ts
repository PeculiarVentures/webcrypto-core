import { AlgorithmNames } from "../alg";
import { BaseCrypto } from "../base";
import { AlgorithmError, CryptoKeyError, WebCryptoError } from "../error";

export class Poly1305 extends BaseCrypto {
    public static ALG_NAME = AlgorithmNames.Poly1305;
    public static KEY_USAGES: string[] = ["sign", "verify"];

    public static checkKeyGenUsages(keyUsages: string[]) {
        this.checkKeyUsages(keyUsages);

        keyUsages.forEach((usage) => {
            let i = 0;
            for (i; i < this.KEY_USAGES.length; i++) {
                if (this.KEY_USAGES[i].toLowerCase() === usage.toLowerCase()) {
                    break;
                }
            }
            if (i === this.KEY_USAGES.length) {
                throw new WebCryptoError(`Unsupported key usage '${usage}'. Should be one of [${this.KEY_USAGES.join(", ")}]`);
            }
        });

    }

    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkKey(key, this.ALG_NAME);
            this.checkFormat(format, key.type);
            resolve(undefined);
        });
    }

    public static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: Poly1305KeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            this.checkFormat(format);
            if (!(format.toLowerCase() === "raw" || format.toLowerCase() === "jwk")) {
                throw new CryptoKeyError(CryptoKeyError.ALLOWED_FORMAT, format, "'jwk' or 'raw'");
            }
            this.checkKeyGenUsages(keyUsages);
            resolve(undefined);
        });
    }

    public static sign(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkKey(key, this.ALG_NAME, "secret", "sign");
            resolve(undefined);
        });
    }

    public static verify(algorithm: Algorithm, key: CryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            this.checkKey(key, this.ALG_NAME, "secret", "verify");
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

interface Poly1305KeyGenParams extends Algorithm {
    length: number;
}
