import { AlgorithmError, WebCryptoError, CryptoKeyError } from "../error";
import { BaseCrypto } from "../base";
import { AlgorithmNames } from "../alg";

export class Hmac extends BaseCrypto {
    protected static ALG_NAME = AlgorithmNames.Hmac;
    protected static KEY_USAGES: string[] = ["sign", "verify"];

    static checkAlgorithm(alg: Algorithm) {
        if (alg.name.toUpperCase() !== this.ALG_NAME.toUpperCase())
            throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg.name, this.ALG_NAME);
    }

    static checkKeyGenParams(alg: AesKeyGenParams) {
        // length is optional
        if ("length" in alg && !(alg.length > 0 && alg.length <= 512)) {
            throw new AlgorithmError(AlgorithmError.PARAM_WRONG_VALUE, "length", "more 0 and less than 512");
        }
    }

    static checkKeyGenUsages(keyUsages: string[]) {
        this.checkKeyUsages(keyUsages);

        keyUsages.forEach(usage => {
            let i = 0;
            for (i; i < this.KEY_USAGES.length; i++)
                if (this.KEY_USAGES[i].toLowerCase() === usage.toLowerCase()) {
                    break;
                }
            if (i === this.KEY_USAGES.length)
                throw new WebCryptoError(`Unsuported key usage '${usage}'. Should be one of [${this.KEY_USAGES.join(", ")}]`);
        });

    }

    static generateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithm(algorithm);
            this.checkKeyGenParams(algorithm);
            this.checkKeyGenUsages(keyUsages);
            resolve(undefined);
        });
    }

    static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkKey(key, this.ALG_NAME);
            this.checkFormat(format, key.type);
            resolve(undefined);
        });
    }
    static importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithm(algorithm);
            this.checkFormat(format);
            if (!(format.toLowerCase() === "raw" || format.toLowerCase() === "jwk"))
                throw new CryptoKeyError(CryptoKeyError.ALLOWED_FORMAT, format, "'jwk' or 'raw'");
            this.checkKeyGenUsages(keyUsages);
            resolve(undefined);
        });
    }
    static sign(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithmParams(algorithm);
            this.checkKey(key, this.ALG_NAME, "secret", "sign");
            resolve(undefined);
        });
    }
    static verify(algorithm: Algorithm, key: CryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithmParams(algorithm);
            this.checkKey(key, this.ALG_NAME, "secret", "verify");
            resolve(undefined);
        });
    }
}