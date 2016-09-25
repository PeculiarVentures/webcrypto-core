type NativeCrypto = Crypto;
type NativeSubtleCrypto = SubtleCrypto;

namespace webcrypto {

    const {RsaOAEP, RsaPSS, RsaSSA, Sha} = rsa;
    const {AesCBC, AesCTR, AesGCM} = aes;
    const {EcDH, EcDSA} = ec;

    export class SubtleCrypto implements NativeSubtleCrypto {
        generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm);
                let Class = BaseCrypto;
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.RsaSSA.toUpperCase():
                        Class = RsaSSA;
                        break;
                    case AlgorithmNames.RsaOAEP.toUpperCase():
                        Class = RsaOAEP;
                        break;
                    case AlgorithmNames.RsaPSS.toUpperCase():
                        Class = RsaPSS;
                        break;
                    case AlgorithmNames.AesCBC.toUpperCase():
                        Class = AesCBC;
                        break;
                    case AlgorithmNames.AesCTR.toUpperCase():
                        Class = AesCTR;
                        break;
                    case AlgorithmNames.AesGCM.toUpperCase():
                        Class = AesGCM;
                        break;
                    case AlgorithmNames.EcDSA.toUpperCase():
                        Class = EcDSA;
                        break;
                    case AlgorithmNames.EcDH.toUpperCase():
                        Class = EcDH;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
                }
                Class.generateKey(alg, extractable, keyUsages).then(resolve, reject);
            });
        }
        digest(algorithm: AlgorithmIdentifier, data: BufferSource): PromiseLike<ArrayBuffer> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm);
                const buf = PrepareData(data, "data");
                let Class = BaseCrypto;
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.Sha1.toUpperCase():
                    case AlgorithmNames.Sha256.toUpperCase():
                    case AlgorithmNames.Sha384.toUpperCase():
                    case AlgorithmNames.Sha512.toUpperCase():
                        Class = Sha;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
                }
                Class.digest(alg, buf).then(resolve, reject);
            });

        }
        sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm as any);
                const buf = PrepareData(data, "data");
                let Class = BaseCrypto;
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.RsaSSA.toUpperCase():
                        Class = RsaSSA;
                        break;
                    case AlgorithmNames.RsaPSS.toUpperCase():
                        Class = RsaPSS;
                        break;
                    case AlgorithmNames.EcDSA.toUpperCase():
                        Class = EcDSA;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
                }
                Class.sign(alg, key, buf).then(resolve, reject);
            });
        }
        verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: BufferSource, data: BufferSource): PromiseLike<boolean> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm as any);
                const sigBuf = PrepareData(data, "signature");
                const buf = PrepareData(data, "data");
                let Class = BaseCrypto;
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.RsaSSA.toUpperCase():
                        Class = RsaSSA;
                        break;
                    case AlgorithmNames.RsaPSS.toUpperCase():
                        Class = RsaPSS;
                        break;
                    case AlgorithmNames.EcDSA.toUpperCase():
                        Class = EcDSA;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
                }
                Class.verify(alg, key, sigBuf, buf).then(resolve, reject);
            });
        }
        encrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm);
                const buf = PrepareData(data, "data");
                let Class = BaseCrypto;
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.RsaOAEP.toUpperCase():
                        Class = RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toUpperCase():
                        Class = AesCBC;
                        break;
                    case AlgorithmNames.AesCTR.toUpperCase():
                        Class = AesCTR;
                        break;
                    case AlgorithmNames.AesGCM.toUpperCase():
                        Class = AesGCM;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
                }
                Class.encrypt(alg, key, buf).then(resolve, reject);
            });
        }
        decrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm);
                const buf = PrepareData(data, "data");
                let Class = BaseCrypto;
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.RsaOAEP.toUpperCase():
                        Class = RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toUpperCase():
                        Class = AesCBC;
                        break;
                    case AlgorithmNames.AesCTR.toUpperCase():
                        Class = AesCTR;
                        break;
                    case AlgorithmNames.AesGCM.toUpperCase():
                        Class = AesGCM;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
                }
                Class.decrypt(alg, key, buf).then(resolve, reject);
            });
        }
        deriveBits(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm);
                let Class = BaseCrypto;
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.EcDH.toUpperCase():
                        Class = EcDH;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
                }
                Class.deriveBits(alg, baseKey, length).then(resolve, reject);
            });
        }
        deriveKey(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm);
                const derivedAlg = PrepareAlgorithm(derivedKeyType);
                let Class = BaseCrypto;
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.EcDH.toUpperCase():
                        Class = EcDH;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
                }
                Class.deriveKey(alg, baseKey, derivedAlg, extractable, keyUsages).then(resolve, reject);
            });
        }
        exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
            return new Promise((resolve, reject) => {
                BaseCrypto.checkKey(key);
                if (!key.extractable)
                    throw new CryptoKeyError(CryptoKeyError.NOT_EXTRACTABLE);
                let Class = BaseCrypto;
                switch (key.algorithm.name.toUpperCase()) {
                    case AlgorithmNames.RsaSSA.toUpperCase():
                        Class = RsaSSA;
                        break;
                    case AlgorithmNames.RsaPSS.toUpperCase():
                        Class = RsaPSS;
                        break;
                    case AlgorithmNames.RsaOAEP.toUpperCase():
                        Class = RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toUpperCase():
                        Class = AesCBC;
                        break;
                    case AlgorithmNames.AesCTR.toUpperCase():
                        Class = AesCTR;
                        break;
                    case AlgorithmNames.AesGCM.toUpperCase():
                        Class = AesGCM;
                        break;
                    case AlgorithmNames.EcDSA.toUpperCase():
                        Class = EcDSA;
                        break;
                    case AlgorithmNames.EcDH.toUpperCase():
                        Class = EcDH;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                }
                Class.exportKey(format, key).then(resolve, reject);
            });
        }
        importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm);
                let Class = BaseCrypto;
                // TODO prepare keyData
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.RsaSSA.toUpperCase():
                        Class = RsaSSA;
                        break;
                    case AlgorithmNames.RsaPSS.toUpperCase():
                        Class = RsaPSS;
                        break;
                    case AlgorithmNames.RsaOAEP.toUpperCase():
                        Class = RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toUpperCase():
                        Class = AesCBC;
                        break;
                    case AlgorithmNames.AesCTR.toUpperCase():
                        Class = AesCTR;
                        break;
                    case AlgorithmNames.AesGCM.toUpperCase():
                        Class = AesGCM;
                        break;
                    case AlgorithmNames.EcDSA.toUpperCase():
                        Class = EcDSA;
                        break;
                    case AlgorithmNames.EcDH.toUpperCase():
                        Class = EcDH;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
                }
                Class.importKey(format, keyData, alg, extractable, keyUsages).then(resolve, reject);
            });
        }
        wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(wrapAlgorithm);
                let Class = BaseCrypto;
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.RsaOAEP.toUpperCase():
                        Class = RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toUpperCase():
                        Class = AesCBC;
                        break;
                    case AlgorithmNames.AesCTR.toUpperCase():
                        Class = AesCTR;
                        break;
                    case AlgorithmNames.AesGCM.toUpperCase():
                        Class = AesGCM;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
                }
                Class.wrapKey(format, key, wrappingKey, alg).then(resolve, reject);
            });
        }
        unwrapKey(format: string, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
            return new Promise((resolve, reject) => {
                const unwrapAlg = PrepareAlgorithm(unwrapAlgorithm);
                const unwrappedAlg = PrepareAlgorithm(unwrappedKeyAlgorithm);
                const buf = PrepareData(wrappedKey, "wrappedKey");
                let Class = BaseCrypto;
                switch (unwrapAlg.name.toUpperCase()) {
                    case AlgorithmNames.RsaOAEP.toUpperCase():
                        Class = RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toUpperCase():
                        Class = AesCBC;
                        break;
                    case AlgorithmNames.AesCTR.toUpperCase():
                        Class = AesCTR;
                        break;
                    case AlgorithmNames.AesGCM.toUpperCase():
                        Class = AesGCM;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, unwrapAlg.name);
                }
                Class.unwrapKey(format, buf, unwrappingKey, unwrapAlg, unwrappedAlg, extractable, keyUsages).then(resolve, reject);
            });
        }
    }

}