import * as Aes from "../aes/crypto";
import { AlgorithmNames } from "../alg";
import { BaseCrypto, PrepareAlgorithm } from "../base";
import { AlgorithmError, CryptoKeyError, WebCryptoError } from "../error";
import { Hmac } from "../hmac/crypto";
import { Sha } from "../sha/crypto";

export class Pbkdf2 extends BaseCrypto {

    public static ALG_NAME = AlgorithmNames.Pbkdf2;
    public static KEY_USAGES: string[] = ["deriveKey", "deriveBits"];

    public static checkAlgorithm(alg: Algorithm) {
        if (alg.name.toUpperCase() !== this.ALG_NAME.toUpperCase()) {
            throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg.name, this.ALG_NAME);
        }
    }

    public static checkDeriveParams(alg: Pbkdf2Params) {
        this.checkAlgorithm(alg);

        // salt
        if (alg.salt) {
            if (!(ArrayBuffer.isView(alg.salt) || alg.salt instanceof ArrayBuffer)) {
                throw new AlgorithmError(AlgorithmError.PARAM_WRONG_TYPE, "salt", "ArrayBuffer or ArrayBufferView");
            }
        } else {
            throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, "salt");
        }

        // iterations
        if (!alg.iterations) {
            throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, "iterations");
        }

        // hash
        if (!alg.hash) {
            throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, "hash");
        }
        const hash = PrepareAlgorithm(alg.hash);
        Sha.checkAlgorithm(hash);
    }

    public static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return Promise.resolve()
            .then(() => {
                if (extractable) {
                    throw new WebCryptoError("KDF keys must set extractable=false");
                }
                this.checkAlgorithm(algorithm as Algorithm);
                this.checkFormat(format);
                if (format.toLowerCase() !== "raw") {
                    throw new CryptoKeyError(CryptoKeyError.ALLOWED_FORMAT, format, "'raw'");
                }
                this.checkKeyUsages(keyUsages);
            }) as any;
    }

    public static deriveKey(algorithm: Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return Promise.resolve()
            .then(() => {
                this.checkDeriveParams(algorithm);
                this.checkKey(baseKey, this.ALG_NAME, "secret", "deriveKey");
                BaseCrypto.checkAlgorithm(derivedKeyType);
                // AES-CTR, AES-CBC, AES-CMAC, AES-GCM, AES-CFB, AES-KW, ECDH, DH, or HMAC
                switch (derivedKeyType.name.toUpperCase()) {
                    case AlgorithmNames.AesCBC:
                        Aes.AesCBC.checkKeyGenParams(derivedKeyType as AesDerivedKeyParams);
                        Aes.AesCBC.checkKeyUsages(keyUsages);
                        break;
                    case AlgorithmNames.AesCTR:
                        Aes.AesCTR.checkKeyGenParams(derivedKeyType as AesDerivedKeyParams);
                        Aes.AesCTR.checkKeyUsages(keyUsages);
                        break;
                    case AlgorithmNames.AesGCM:
                        Aes.AesGCM.checkKeyGenParams(derivedKeyType as AesDerivedKeyParams);
                        Aes.AesGCM.checkKeyUsages(keyUsages);
                        break;
                    case AlgorithmNames.AesKW:
                        Aes.AesKW.checkKeyGenParams(derivedKeyType as AesDerivedKeyParams);
                        Aes.AesKW.checkKeyUsages(keyUsages);
                        break;
                    case AlgorithmNames.Hmac:
                        Hmac.checkKeyGenParams(derivedKeyType as any);
                        Hmac.checkKeyUsages(keyUsages);
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, derivedKeyType);
                }
            }) as any;
    }

    public static deriveBits(algorithm: Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                this.checkDeriveParams(algorithm);
                this.checkKey(baseKey, this.ALG_NAME, "secret", "deriveBits");
                if (!(length && typeof length === "number")) {
                    throw new WebCryptoError("Parameter 'length' must be Number and more than 0");
                }
            }) as any;
    }
}
