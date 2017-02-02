import { AesCBC, AesCTR, AesGCM, AesKW } from "../aes/crypto";
import { Sha } from "../sha/crypto";
import { WebCryptoError, AlgorithmError, CryptoKeyError } from "../error";
import { BaseCrypto } from "../base";
import { AlgorithmNames } from "../alg";

export class EcKeyGenParamsError extends AlgorithmError {
    code = 9;
}

export class Ec extends BaseCrypto {
    protected static ALG_NAME = "";
    protected static KEY_USAGES: string[] = [];

    static checkAlgorithm(alg: Algorithm) {
        if (alg.name.toUpperCase() !== this.ALG_NAME.toUpperCase())
            throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg.name, this.ALG_NAME);
    }

    static checkKeyGenParams(alg: EcKeyGenParams) {
        const param_namedCurve = "namedCurve";
        if (!alg.namedCurve)
            throw new EcKeyGenParamsError(EcKeyGenParamsError.PARAM_REQUIRED, param_namedCurve);
        if (!(typeof alg.namedCurve === "string"))
            throw new EcKeyGenParamsError(EcKeyGenParamsError.PARAM_WRONG_TYPE, param_namedCurve, "string");
        switch (alg.namedCurve.toUpperCase()) {
            case "P-256":
            case "P-384":
            case "P-521":
                break;
            default:
                throw new EcKeyGenParamsError(EcKeyGenParamsError.PARAM_WRONG_VALUE, param_namedCurve, "P-256, P-384 or P-521");
        }
    }

    static checkKeyGenUsages(keyUsages: string[]) {
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

    static generateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair> {
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
            if (!(format && format.toLowerCase() === "raw" && key.type === "public"))
            this.checkFormat(format, key.type);
            resolve(undefined);
        });
    }
    static importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            this.checkKeyGenParams(algorithm);
            this.checkFormat(format);
            this.checkKeyGenUsages(keyUsages);
            resolve(undefined);
        });
    }
}

export class EcAlgorithmError extends AlgorithmError {
    code = 10;
}

export class EcDSA extends Ec {
    protected static ALG_NAME = AlgorithmNames.EcDSA;
    protected static KEY_USAGES: string[] = ["sign", "verify", "deriveKey", "deriveBits"];

    static checkAlgorithmParams(alg: EcdsaParams) {
        this.checkAlgorithm(alg);
        Sha.checkAlgorithm(alg.hash as Algorithm);
    }

    static sign(algorithm: EcdsaParams, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithmParams(algorithm);
            this.checkKey(key, this.ALG_NAME, "private", "sign");
            resolve(undefined);
        });
    }

    static verify(algorithm: EcdsaParams, key: CryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithmParams(algorithm);
            this.checkKey(key, this.ALG_NAME, "public", "verify");
            resolve(undefined);
        });
    }

}

export class EcDH extends Ec {
    protected static ALG_NAME = AlgorithmNames.EcDH;
    protected static KEY_USAGES: string[] = ["deriveKey", "deriveBits"];

    static checkDeriveParams(algorithm: EcdhKeyDeriveParams) {
        const param_public = "public";
        this.checkAlgorithm(algorithm);
        if (!algorithm.public)
            throw new EcAlgorithmError(EcAlgorithmError.PARAM_REQUIRED, param_public);
        this.checkKey(algorithm.public, this.ALG_NAME, "public");
    }

    static deriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkDeriveParams(algorithm);
            this.checkKey(baseKey, this.ALG_NAME, "private", "deriveBits");
            resolve(undefined);
        });
    }
    static deriveKey(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, derivedKeyType: AesDerivedKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            this.checkDeriveParams(algorithm);
            this.checkKey(baseKey, this.ALG_NAME, "private", "deriveKey");
            BaseCrypto.checkAlgorithm(derivedKeyType);
            switch (derivedKeyType.name.toUpperCase()) {
                case AlgorithmNames.AesCBC:
                    AesCBC.checkKeyGenParams(derivedKeyType);
                    break;
                case AlgorithmNames.AesCTR:
                    AesCTR.checkKeyGenParams(derivedKeyType);
                    break;
                case AlgorithmNames.AesGCM:
                    AesGCM.checkKeyGenParams(derivedKeyType);
                    break;
                case AlgorithmNames.AesKW:
                    AesKW.checkKeyGenParams(derivedKeyType);
                    break;
                default:
                    throw new EcAlgorithmError(`Unsupported name '${derivedKeyType.name}' for algorithm in param 'derivedKeyType'`);
            }
            resolve(undefined);
        });
    }
}