import { AlgorithmError, CryptoKeyError, WebCryptoError } from "./error";

export function PrepareAlgorithm(alg: AlgorithmIdentifier | string): Algorithm {
    let res: Algorithm;
    if (typeof alg === "string") {
        res = { name: alg };
    } else {
        res = alg;
    }
    BaseCrypto.checkAlgorithm(res);
    const hashedAlg: RsaHashedKeyAlgorithm = alg as any;
    if (hashedAlg.hash) {
        hashedAlg.hash = PrepareAlgorithm(hashedAlg.hash);
    }
    return res;
}

export function PrepareData(data: BufferSource, paramName: string): Uint8Array {
    if (!data) {
        throw new WebCryptoError(`Parameter '${paramName}' is required and cant be empty`);
    }
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(data)) {
        return new Uint8Array(data as Buffer);
    }
    if (ArrayBuffer.isView(data)) {
        // Copy data, because `data.buffer` can has another buffer size after ArrayBufferView.subarray
        const copy = (data as Uint8Array).map((i) => i);
        return new Uint8Array(copy.buffer);
    }
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }
    throw new WebCryptoError(`Incoming parameter '${paramName}' has wrong data type. Must be ArrayBufferView or ArrayBuffer`);
}

export class BaseCrypto {

    public static checkAlgorithm(alg: Algorithm) {
        if (typeof alg !== "object") {
            throw new TypeError("Wrong algorithm data type. Must be Object");
        }
        if (!alg.name) {
            throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, "name");
        }
    }

    public static checkAlgorithmParams(alg: Algorithm) {
        this.checkAlgorithm(alg);
    }

    public static checkKey(key: CryptoKey, alg?: string, type: string | null = null, usage: string | null = null) {
        // check key empty
        if (!key) {
            throw new CryptoKeyError(CryptoKeyError.EMPTY_KEY);
        }
        // check alg
        const keyAlg = key.algorithm;
        this.checkAlgorithm(keyAlg as Algorithm);
        if (alg && (keyAlg.name!.toUpperCase() !== alg.toUpperCase())) {
            throw new CryptoKeyError(CryptoKeyError.WRONG_KEY_ALG, keyAlg.name, alg);
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

    public static checkWrappedKey(key: CryptoKey) {
        if (!key.extractable) {
            throw new CryptoKeyError(CryptoKeyError.NOT_EXTRACTABLE);
        }
    }

    public static checkKeyUsages(keyUsages: string[]) {
        if (!keyUsages || !keyUsages.length) {
            throw new WebCryptoError("Parameter 'keyUsages' cannot be empty.");
        }
    }

    public static checkFormat(format: string, type?: string) {
        switch (format.toLowerCase()) {
            case "raw":
                if (type && type.toLowerCase() !== "secret" && type && type.toLowerCase() !== "public") {
                    throw new CryptoKeyError(CryptoKeyError.WRONG_FORMAT, type, "raw");
                }
                break;
            case "pkcs8":
                if (type && type.toLowerCase() !== "private") {
                    throw new CryptoKeyError(CryptoKeyError.WRONG_FORMAT, type, "pkcs8");
                }
                break;
            case "spki":
                if (type && type.toLowerCase() !== "public") {
                    throw new CryptoKeyError(CryptoKeyError.WRONG_FORMAT, type, "spki");
                }
                break;
            case "jwk":
                break;
            default:
                throw new CryptoKeyError(CryptoKeyError.UNKNOWN_FORMAT, format);
        }
    }

    public static generateKey(algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static digest(algorithm: Algorithm, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static sign(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static verify(algorithm: Algorithm, key: CryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static encrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static decrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static deriveKey(algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

    public static unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    }

}
