namespace webcrypto {

    const {RsaOAEP, RsaPSS, RsaSSA, Sha} = rsa;
    const {AesCBC, AesCTR, AesGCM} = aes;
    const {EcDH, EcDSA} = ec;

    export interface NodeSubtleCrypto extends SubtleCrypto {
        generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair>;
        digest(algorithm: AlgorithmIdentifier, data: CryptoBuffer): PromiseLike<ArrayBuffer>;
        sign(algorithm: AlgorithmIdentifier, key: CryptoKey, data: CryptoBuffer): PromiseLike<ArrayBuffer>;
        verify(algorithm: AlgorithmIdentifier, key: CryptoKey, signature: CryptoBuffer, data: CryptoBuffer): PromiseLike<boolean>;
        encrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: CryptoBuffer): PromiseLike<ArrayBuffer>;
        decrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: CryptoBuffer): PromiseLike<ArrayBuffer>;
        deriveBits(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
        deriveKey(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        exportKey(format: string, key: CryptoKey): PromiseLike<JWK | ArrayBuffer>;
        importKey(format: string, keyData: JWK | CryptoBuffer, algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer>;
        unwrapKey(format: string, wrappedKey: CryptoBuffer, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    }

    export class Subtle implements NodeSubtleCrypto {
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
        digest(algorithm: AlgorithmIdentifier, data: CryptoBuffer): PromiseLike<ArrayBuffer> {
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
        sign(algorithm: AlgorithmIdentifier, key: CryptoKey, data: CryptoBuffer): PromiseLike<ArrayBuffer> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm);
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
        verify(algorithm: AlgorithmIdentifier, key: CryptoKey, signature: CryptoBuffer, data: CryptoBuffer): PromiseLike<boolean> {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm);
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
        encrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: CryptoBuffer): PromiseLike<ArrayBuffer> {
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
        decrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: CryptoBuffer): PromiseLike<ArrayBuffer> {
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
        exportKey(format: string, key: CryptoKey): PromiseLike<JWK | ArrayBuffer> {
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
        importKey(format: string, keyData: JWK | CryptoBuffer, algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
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
        unwrapKey(format: string, wrappedKey: CryptoBuffer, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
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