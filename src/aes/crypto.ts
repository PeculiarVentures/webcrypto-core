import { AlgorithmNames } from "../alg";
import { BaseCrypto } from "../base";
import { AlgorithmError, CryptoKeyError, WebCryptoError } from "../error";

class AesKeyGenParamsError extends AlgorithmError {
    public code = 7;
}

export class Aes extends BaseCrypto {

    public static ALG_NAME = "";
    public static KEY_USAGES: string[] = [];

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

    public static checkKeyGenParams(alg: AesKeyGenParams) {
        switch (alg.length) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new AesKeyGenParamsError(AesKeyGenParamsError.PARAM_WRONG_VALUE, "length", "128, 192 or 256");
        }
    }

    public static generateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair> {
        return new Promise((resolve, reject) => {
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
        return new Promise((resolve, reject) => {
            this.checkAlgorithm(algorithm);
            this.checkFormat(format);
            if (!(format.toLowerCase() === "raw" || format.toLowerCase() === "jwk")) {
                throw new CryptoKeyError(CryptoKeyError.ALLOWED_FORMAT, format, "'jwk' or 'raw'");
            }
            this.checkKeyUsages(keyUsages);
            resolve(undefined);
        });
    }
}

export class AesAlgorithmError extends AlgorithmError {
    public code = 8;
}

export class AesWrapKey extends Aes {

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

}

export class AesEncrypt extends AesWrapKey {

    public static KEY_USAGES: string[] = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

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

export class AesECB extends AesEncrypt {
    public static ALG_NAME = AlgorithmNames.AesECB;
}

export class AesCBC extends AesEncrypt {

    public static ALG_NAME = AlgorithmNames.AesCBC;

    public static checkAlgorithmParams(alg: AesCbcParams) {
        this.checkAlgorithm(alg);
        if (!alg.iv) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_REQUIRED, "iv");
        }
        if (!(ArrayBuffer.isView(alg.iv) || alg.iv instanceof ArrayBuffer)) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "iv", "ArrayBufferView or ArrayBuffer");
        }
        if (alg.iv.byteLength !== 16) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "iv", "ArrayBufferView or ArrayBuffer with size 16");
        }
    }

}

export class AesCTR extends AesEncrypt {

    public static ALG_NAME = AlgorithmNames.AesCTR;

    public static checkAlgorithmParams(alg: AesCtrParams) {
        this.checkAlgorithm(alg);
        if (!(alg.counter && (ArrayBuffer.isView(alg.counter) || alg.counter instanceof ArrayBuffer))) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "counter", "ArrayBufferView or ArrayBuffer");
        }
        if (alg.counter.byteLength !== 16) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "counter", "ArrayBufferView or ArrayBuffer with size 16");
        }
        if (!(alg.length > 0 && alg.length <= 128)) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "length", "number [1-128]");
        }
    }

}

export class AesGCM extends AesEncrypt {

    public static ALG_NAME = AlgorithmNames.AesGCM;

    public static checkAlgorithmParams(alg: AesGcmParams) {
        this.checkAlgorithm(alg);
        if (alg.additionalData) {
            if (!(ArrayBuffer.isView(alg.additionalData) || alg.additionalData instanceof ArrayBuffer)) {
                throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "additionalData", "ArrayBufferView or ArrayBuffer");
            }
        }
        // If the iv member of normalizedAlgorithm has a length greater than 2^64 - 1 bytes, then throw an OperationError.
        if (!alg.iv) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_REQUIRED, "iv");
        }
        if (!(ArrayBuffer.isView(alg.iv) || alg.iv instanceof ArrayBuffer)) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "iv", "ArrayBufferView or ArrayBuffer");
        }
        // If the tagLength member of normalizedAlgorithm is not present: Let tagLength be 128.
        if (alg.tagLength) {
            // If the tagLength member of normalizedAlgorithm is one of 32, 64, 96, 104, 112, 120 or 128:
            // Let tagLength be equal to the tagLength member of normalizedAlgorithm
            const ok = [32, 64, 96, 104, 112, 120, 128].some((tagLength) => {
                return tagLength === alg.tagLength;
            });
            if (!ok) {
                throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "tagLength", "32, 64, 96, 104, 112, 120 or 128");
            }
        }
    }

}

export class AesKW extends AesWrapKey {

    public static ALG_NAME = AlgorithmNames.AesKW;
    public static KEY_USAGES: string[] = ["wrapKey", "unwrapKey"];

    public static checkAlgorithmParams(alg: AesGcmParams) {
        this.checkAlgorithm(alg);
    }

}
