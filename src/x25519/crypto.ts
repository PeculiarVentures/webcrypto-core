import { AlgorithmNames } from "../alg";
import { BaseCrypto } from "../base";
import { ChaCha20 } from "../chacha20/crypto";
import { AlgorithmError, CryptoKeyError, WebCryptoError } from "../error";

export class X25519 extends BaseCrypto {

    public static ALG_NAME = AlgorithmNames.X25519;
    public static KEY_USAGES: string[] = ["deriveKey", "deriveBits"];

    public static checkDeriveParams(algorithm: X25519KeyDeriveParams) {
        const paramPublic = "public";
        this.checkAlgorithm(algorithm);
        if (!algorithm.public) {
            throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, paramPublic);
        }
        this.checkKey(algorithm.public, this.ALG_NAME, "public");
    }

    public static deriveBits(algorithm: X25519KeyDeriveParams, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkDeriveParams(algorithm);
            this.checkKey(baseKey, this.ALG_NAME, "private", "deriveBits");
            resolve(undefined);
        });
    }

    public static deriveKey(algorithm: X25519KeyDeriveParams, baseKey: CryptoKey, derivedKeyType: AesDerivedKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            this.checkDeriveParams(algorithm);
            this.checkKey(baseKey, this.ALG_NAME, "private", "deriveKey");
            BaseCrypto.checkAlgorithm(derivedKeyType);
            switch (derivedKeyType.name.toUpperCase()) {
                case AlgorithmNames.ChaCha20:
                    ChaCha20.checkKeyGenParams(derivedKeyType);
                    break;
                default:
                    throw new AlgorithmError(`Unsupported name '${derivedKeyType.name}' for algorithm in param 'derivedKeyType'`);
            }
            resolve(undefined);
        });
    }
}

interface X25519KeyDeriveParams extends Algorithm {
    public: CryptoKey;
}
