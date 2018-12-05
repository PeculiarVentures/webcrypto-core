import { AlgorithmNames } from "./alg";
import { BaseCrypto, PrepareAlgorithm, PrepareData } from "./base";
import { AlgorithmError, CryptoKeyError, WebCryptoError } from "./error";

import { AesCBC, AesCTR, AesECB, AesGCM, AesKW } from "./aes/crypto";
import { ChaCha20 } from "./chacha20/crypto";
import { Des, DesCBC, DesCbcParams } from "./des/crypto";
import { EcDH, EcDSA, EdDSA } from "./ec/crypto";
import { Hmac } from "./hmac/crypto";
import { Pbkdf2 } from "./pbkdf2/crypto";
import { Poly1305 } from "./poly1305/crypto";
import { RsaOAEP, RsaPSS, RsaSSA } from "./rsa/crypto";
import { Sha } from "./sha/crypto";

export class SubtleCrypto implements NativeSubtleCrypto {

    public generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey>;
    public generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;
    public generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey> {
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
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
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
                case AlgorithmNames.AesKW.toUpperCase():
                    Class = AesKW;
                    break;
                case AlgorithmNames.EcDSA.toUpperCase():
                    Class = EcDSA;
                    break;
                case AlgorithmNames.EdDSA.toUpperCase():
                    Class = EdDSA;
                    break;
                case AlgorithmNames.EcDH.toUpperCase():
                    Class = EcDH;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    Class = Hmac;
                    break;
                case AlgorithmNames.DesCBC.toUpperCase():
                    Class = DesCBC;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.generateKey(alg, extractable, keyUsages).then(resolve, reject);
        });
    }

    public digest(algorithm: AlgorithmIdentifier, data: BufferSource): PromiseLike<ArrayBuffer> {
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

    public sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer>;
    public sign(algorithm: any, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
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
                case AlgorithmNames.EdDSA.toUpperCase():
                    Class = EdDSA;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    Class = Hmac;
                    break;
                case AlgorithmNames.Poly1305.toUpperCase():
                    Class = Poly1305;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.sign(alg, key, buf).then(resolve, reject);
        });
    }

    public verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: BufferSource, data: BufferSource): PromiseLike<boolean>;
    public verify(algorithm: any, key: CryptoKey, signature: BufferSource, data: BufferSource): PromiseLike<boolean> {
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
                case AlgorithmNames.EdDSA.toUpperCase():
                    Class = EdDSA;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    Class = Hmac;
                    break;
                case AlgorithmNames.Poly1305.toUpperCase():
                    Class = Poly1305;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.verify(alg, key, sigBuf, buf).then(resolve, reject);
        });
    }

    public encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | DesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer>;
    public encrypt(algorithm: any, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = PrepareAlgorithm(algorithm);
            const buf = PrepareData(data, "data");
            let Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
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
                case AlgorithmNames.ChaCha20.toUpperCase():
                    Class = ChaCha20;
                    break;
                case AlgorithmNames.DesCBC.toUpperCase():
                    Class = DesCBC;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.encrypt(alg, key, buf).then(resolve, reject);
        });
    }

    public decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | DesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer>;
    public decrypt(algorithm: any, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = PrepareAlgorithm(algorithm);
            const buf = PrepareData(data, "data");
            let Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
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
                case AlgorithmNames.ChaCha20.toUpperCase():
                    Class = ChaCha20;
                    break;
                case AlgorithmNames.DesCBC.toUpperCase():
                    Class = DesCBC;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.decrypt(alg, key, buf).then(resolve, reject);
        });
    }

    public deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
    public deriveBits(algorithm: any, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = PrepareAlgorithm(algorithm);
            let Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.EcDH.toUpperCase():
                    Class = EcDH;
                    break;
                case AlgorithmNames.Pbkdf2.toUpperCase():
                    Class = Pbkdf2;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.deriveBits(alg, baseKey, length).then(resolve, reject);
        });
    }

    public deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | AesDerivedKeyParams | HmacImportParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public deriveKey(algorithm: any, baseKey: CryptoKey, derivedKeyType: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            const alg = PrepareAlgorithm(algorithm);
            const derivedAlg = PrepareAlgorithm(derivedKeyType);
            let Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.EcDH.toUpperCase():
                    Class = EcDH;
                    break;
                case AlgorithmNames.Pbkdf2.toUpperCase():
                    Class = Pbkdf2;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.deriveKey(alg, baseKey, derivedAlg, extractable, keyUsages).then(resolve, reject);
        });
    }

    public exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
    public exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
    public exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
    public exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            BaseCrypto.checkKey(key);
            if (!key.extractable) {
                throw new CryptoKeyError(CryptoKeyError.NOT_EXTRACTABLE);
            }
            let Class = BaseCrypto;
            switch (key.algorithm.name!.toUpperCase()) {
                case AlgorithmNames.RsaSSA.toUpperCase():
                    Class = RsaSSA;
                    break;
                case AlgorithmNames.RsaPSS.toUpperCase():
                    Class = RsaPSS;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
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
                case AlgorithmNames.AesKW.toUpperCase():
                    Class = AesKW;
                    break;
                case AlgorithmNames.EcDSA.toUpperCase():
                    Class = EcDSA;
                    break;
                case AlgorithmNames.EdDSA.toUpperCase():
                    Class = EdDSA;
                    break;
                case AlgorithmNames.EcDH.toUpperCase():
                    Class = EcDH;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    Class = Hmac;
                    break;
                case AlgorithmNames.Poly1305.toUpperCase():
                    Class = Poly1305;
                    break;
                case AlgorithmNames.DesCBC.toUpperCase():
                    Class = DesCBC;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
            }
            Class.exportKey(format, key).then(resolve, reject);
        });
    }

    public importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public importKey(format: "raw" | "pkcs8" | "spki", keyData: BufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
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
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
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
                case AlgorithmNames.AesKW.toUpperCase():
                    Class = AesKW;
                    break;
                case AlgorithmNames.EcDSA.toUpperCase():
                    Class = EcDSA;
                    break;
                case AlgorithmNames.EdDSA.toUpperCase():
                    Class = EdDSA;
                    break;
                case AlgorithmNames.EcDH.toUpperCase():
                    Class = EcDH;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    Class = Hmac;
                    break;
                case AlgorithmNames.Pbkdf2.toUpperCase():
                    Class = Pbkdf2;
                    break;
                case AlgorithmNames.Poly1305.toUpperCase():
                    Class = Poly1305;
                    break;
                case AlgorithmNames.DesCBC.toUpperCase():
                    Class = DesCBC;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.importKey(format, keyData, alg, extractable, keyUsages).then(resolve, reject);
        });
    }

    public wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = PrepareAlgorithm(wrapAlgorithm);
            let Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
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
                case AlgorithmNames.AesKW.toUpperCase():
                    Class = AesKW;
                    break;
                case AlgorithmNames.DesCBC.toUpperCase():
                    Class = DesCBC;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.wrapKey(format, key, wrappingKey, alg).then(resolve, reject);
        });
    }

    public unwrapKey(format: string, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            const unwrapAlg = PrepareAlgorithm(unwrapAlgorithm);
            const unwrappedAlg = PrepareAlgorithm(unwrappedKeyAlgorithm);
            const buf = PrepareData(wrappedKey, "wrappedKey");
            let Class = BaseCrypto;
            switch (unwrapAlg.name.toUpperCase()) {
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
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
                case AlgorithmNames.AesKW.toUpperCase():
                    Class = AesKW;
                    break;
                case AlgorithmNames.DesCBC.toUpperCase():
                    Class = DesCBC;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, unwrapAlg.name);
            }
            Class.unwrapKey(format, buf, unwrappingKey, unwrapAlg, unwrappedAlg, extractable, keyUsages).then(resolve, reject);
        });
    }
}
