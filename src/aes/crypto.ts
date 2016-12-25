import { AlgorithmError, WebCryptoError, CryptoKeyError } from "../error";
import { BaseCrypto } from "../base";
import { AlgorithmNames } from "../alg";

class AesKeyGenParamsError extends AlgorithmError {
    code = 7;
}

export class Aes extends BaseCrypto {
    protected static ALG_NAME = "";
    protected static KEY_USAGES: string[] = [];

    static checkKeyUsages(keyUsages: string[]) {
        super.checkKeyUsages(keyUsages);
        const wron_usage = keyUsages.filter(usage => this.KEY_USAGES.indexOf(usage) === -1);
        if (wron_usage.length)
            throw new AlgorithmError(AlgorithmError.WRONG_USAGE, wron_usage.join(", "));
    }

    static checkAlgorithm(alg: Algorithm) {
        if (alg.name.toUpperCase() !== this.ALG_NAME.toUpperCase())
            throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg.name, this.ALG_NAME);
    }

    static checkKeyGenParams(alg: AesKeyGenParams) {
        switch (alg.length) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new AesKeyGenParamsError(AesKeyGenParamsError.PARAM_WRONG_VALUE, "length", "128, 192 or 256");
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
}

export class AesAlgorithmError extends AlgorithmError {
    code = 8;
}

export class AesWrapKey extends Aes {
    static wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithmParams(wrapAlgorithm);
            this.checkKey(wrappingKey, this.ALG_NAME, "secret", "wrapKey");
            this.checkWrappedKey(key);
            this.checkFormat(format, key.type);
            resolve(undefined);
        });
    }
    static unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
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
    protected static KEY_USAGES: string[] = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

    static encrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithmParams(algorithm);
            this.checkKey(key, this.ALG_NAME, "secret", "encrypt");
            resolve(undefined);
        });
    }
    static decrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithmParams(algorithm);
            this.checkKey(key, this.ALG_NAME, "secret", "decrypt");
            resolve(undefined);
        });
    }
}

export class AesCBC extends AesEncrypt {
    protected static ALG_NAME = AlgorithmNames.AesCBC;

    static checkAlgorithmParams(alg: AesCbcParams) {
        this.checkAlgorithm(alg);
        if (!alg.iv)
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_REQUIRED, "iv");
        if (!ArrayBuffer.isView(alg.iv))
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "iv", "ArrayBufferView");
        if (alg.iv.byteLength !== 16)
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "iv", "ArrayBufferView with size 16");
    }

}

export class AesCTR extends AesEncrypt {
    protected static ALG_NAME = AlgorithmNames.AesCTR;

    static checkAlgorithmParams(alg: AesCtrParams) {
        this.checkAlgorithm(alg);
        if (!(alg.counter && ArrayBuffer.isView(alg.counter)))
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "counter", "ArrayBufferView");
        if (alg.counter.byteLength !== 16)
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "counter", "ArrayBufferView with size 16");
        if (!(alg.length > 0 && alg.length <= 128))
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "length", "number [1-128]");
    }

}
export class AesGCM extends AesEncrypt {
    protected static ALG_NAME = AlgorithmNames.AesGCM;

    static checkAlgorithmParams(alg: AesGcmParams) {
        this.checkAlgorithm(alg);
        if (alg.additionalData)
            if (!ArrayBuffer.isView(alg.additionalData))
                throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "additionalData", "ArrayBufferView");
        if (!alg.iv)
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_REQUIRED, "iv");
        if (!ArrayBuffer.isView(alg.iv))
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "iv", "ArrayBufferView");
        if (alg.tagLength)
            if (!(alg.tagLength >= 0 && alg.tagLength <= 128))
                throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "tagLength", "number [0-128]");
    }

}

export class AesKW extends AesWrapKey {
    protected static ALG_NAME = AlgorithmNames.AesKW;
    protected static KEY_USAGES: string[] = ["wrapKey", "unwrapKey"];

    static checkAlgorithmParams(alg: AesGcmParams) {
        this.checkAlgorithm(alg);
    }

}