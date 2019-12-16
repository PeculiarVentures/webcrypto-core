import { BufferSourceConverter, Convert } from "pvtsutils";
import { AlgorithmError } from "./errors";
import { CryptoKey } from "./key";
import { ProviderCrypto } from "./provider";
import { ProviderStorage } from "./storage";
import { HashedAlgorithm } from "./types";

export class SubtleCrypto {

    public static isHashedAlgorithm(data: any): data is HashedAlgorithm {
        return data instanceof Object
            && "name" in data
            && "hash" in data;
    }

    protected providers = new ProviderStorage();

    public async digest(algorithm: AlgorithmIdentifier, data: BufferSource): Promise<ArrayBuffer> {
        this.checkRequiredArguments(arguments, 2, "digest");

        const preparedAlgorithm = this.prepareAlgorithm(algorithm);
        const preparedData = BufferSourceConverter.toArrayBuffer(data);

        const provider = this.getProvider(preparedAlgorithm.name);
        const result = await provider.digest(preparedAlgorithm, preparedData);

        return result;
    }

    public async generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair | CryptoKey> {
        this.checkRequiredArguments(arguments, 3, "generateKey");

        const preparedAlgorithm = this.prepareAlgorithm(algorithm);

        const provider = this.getProvider(preparedAlgorithm.name);
        const result = await provider.generateKey({ ...preparedAlgorithm, name: provider.name }, extractable, keyUsages);

        return result;
    }

    public async sign(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        this.checkRequiredArguments(arguments, 3, "sign");
        this.checkCryptoKey(key);

        const preparedAlgorithm = this.prepareAlgorithm(algorithm);
        const preparedData = BufferSourceConverter.toArrayBuffer(data);

        const provider = this.getProvider(preparedAlgorithm.name);
        const result = await provider.sign({ ...preparedAlgorithm, name: provider.name }, key, preparedData);

        return result;
    }

    public async verify(algorithm: AlgorithmIdentifier, key: CryptoKey, signature: BufferSource, data: BufferSource): Promise<boolean> {
        this.checkRequiredArguments(arguments, 4, "verify");
        this.checkCryptoKey(key);

        const preparedAlgorithm = this.prepareAlgorithm(algorithm);
        const preparedData = BufferSourceConverter.toArrayBuffer(data);
        const preparedSignature = BufferSourceConverter.toArrayBuffer(signature);

        const provider = this.getProvider(preparedAlgorithm.name);
        const result = await provider.verify({ ...preparedAlgorithm, name: provider.name }, key, preparedSignature, preparedData);

        return result;
    }

    public async encrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        this.checkRequiredArguments(arguments, 3, "encrypt");
        this.checkCryptoKey(key);

        const preparedAlgorithm = this.prepareAlgorithm(algorithm);
        const preparedData = BufferSourceConverter.toArrayBuffer(data);

        const provider = this.getProvider(preparedAlgorithm.name);
        const result = await provider.encrypt({ ...preparedAlgorithm, name: provider.name }, key, preparedData, { keyUsage: true });

        return result;
    }

    public async decrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        this.checkRequiredArguments(arguments, 3, "decrypt");
        this.checkCryptoKey(key);

        const preparedAlgorithm = this.prepareAlgorithm(algorithm);
        const preparedData = BufferSourceConverter.toArrayBuffer(data);

        const provider = this.getProvider(preparedAlgorithm.name);
        const result = await provider.decrypt({ ...preparedAlgorithm, name: provider.name }, key, preparedData, { keyUsage: true });

        return result;
    }

    public async deriveBits(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
        this.checkRequiredArguments(arguments, 3, "deriveBits");
        this.checkCryptoKey(baseKey);

        const preparedAlgorithm = this.prepareAlgorithm(algorithm);

        const provider = this.getProvider(preparedAlgorithm.name);
        const result = await provider.deriveBits({ ...preparedAlgorithm, name: provider.name }, baseKey, length, { keyUsage: true });

        return result;
    }

    public async deriveKey(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        this.checkRequiredArguments(arguments, 5, "deriveKey");
        // check derivedKeyType
        const preparedDerivedKeyType = this.prepareAlgorithm(derivedKeyType);
        const importProvider = this.getProvider(preparedDerivedKeyType.name);
        importProvider.checkDerivedKeyParams(preparedDerivedKeyType);

        // derive bits
        const preparedAlgorithm = this.prepareAlgorithm(algorithm);
        const provider = this.getProvider(preparedAlgorithm.name);
        provider.checkCryptoKey(baseKey, "deriveKey");
        const derivedBits = await provider.deriveBits({ ...preparedAlgorithm, name: provider.name }, baseKey, (derivedKeyType as any).length, { keyUsage: false });

        // import derived key
        return this.importKey("raw", derivedBits, derivedKeyType, extractable, keyUsages);
    }

    public async exportKey(format: "raw" | "spki" | "pkcs8", key: CryptoKey): Promise<ArrayBuffer>;
    public async exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;
    public async exportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer>;
    public async exportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
        this.checkRequiredArguments(arguments, 2, "exportKey");
        this.checkCryptoKey(key);

        const provider = this.getProvider(key.algorithm.name);
        const result = await provider.exportKey(format, key);

        return result;
    }
    public async importKey(format: KeyFormat, keyData: JsonWebKey | BufferSource, algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        this.checkRequiredArguments(arguments, 5, "importKey");

        const preparedAlgorithm = this.prepareAlgorithm(algorithm);
        const provider = this.getProvider(preparedAlgorithm.name);

        if (["pkcs8", "spki", "raw"].indexOf(format) !== -1) {
            const preparedData = BufferSourceConverter.toArrayBuffer(keyData as BufferSource);

            return provider.importKey(format, preparedData, { ...preparedAlgorithm, name: provider.name }, extractable, keyUsages);
        } else {
            if (!(keyData as JsonWebKey).kty) {
                throw new TypeError("keyData: Is not JSON");
            }
        }
        return provider.importKey(format, keyData as JsonWebKey, { ...preparedAlgorithm, name: provider.name }, extractable, keyUsages);
    }

    public async wrapKey(format: KeyFormat, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): Promise<ArrayBuffer> {
        let keyData = await this.exportKey(format, key);
        if (format === "jwk") {
            const json = JSON.stringify(keyData);
            keyData = Convert.FromUtf8String(json);
        }

        // encrypt key data
        const preparedAlgorithm = this.prepareAlgorithm(wrapAlgorithm);
        const preparedData = BufferSourceConverter.toArrayBuffer(keyData as ArrayBuffer);
        const provider = this.getProvider(preparedAlgorithm.name);
        return provider.encrypt({ ...preparedAlgorithm, name: provider.name }, wrappingKey, preparedData, { keyUsage: false });
    }

    public async unwrapKey(format: KeyFormat, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        // decrypt wrapped key
        const preparedAlgorithm = this.prepareAlgorithm(unwrapAlgorithm);
        const preparedData = BufferSourceConverter.toArrayBuffer(wrappedKey);
        const provider = this.getProvider(preparedAlgorithm.name);
        let keyData = await provider.decrypt({ ...preparedAlgorithm, name: provider.name }, unwrappingKey, preparedData, { keyUsage: false });
        if (format === "jwk") {
            try {
                keyData = JSON.parse(Convert.ToUtf8String(keyData));
            } catch (e) {
                const error = new TypeError("wrappedKey: Is not a JSON");
                (error as any).internal = e;
                throw error;
            }
        }

        // import key
        return this.importKey(format, keyData, unwrappedKeyAlgorithm, extractable, keyUsages);
    }

    protected checkRequiredArguments(args: IArguments, size: number, methodName: string) {
        if (args.length !== size) {
            throw new TypeError(`Failed to execute '${methodName}' on 'SubtleCrypto': ${size} arguments required, but only ${args.length} present`);
        }
    }

    protected prepareAlgorithm(algorithm: AlgorithmIdentifier): Algorithm | HashedAlgorithm {
        if (typeof algorithm === "string") {
            return {
                name: algorithm,
            } as Algorithm;
        }
        if (SubtleCrypto.isHashedAlgorithm(algorithm)) {
            const preparedAlgorithm = { ...algorithm };
            preparedAlgorithm.hash = this.prepareAlgorithm(algorithm.hash);
            return preparedAlgorithm as HashedAlgorithm;
        }
        return { ...algorithm };
    }

    protected getProvider(name: string): ProviderCrypto {
        const provider = this.providers.get(name);
        if (!provider) {
            throw new AlgorithmError("Unrecognized name");
        }
        return provider;
    }

    protected checkCryptoKey(key: CryptoKey) {
        if (!(key instanceof CryptoKey)) {
            throw new TypeError(`Key is not of type 'CryptoKey'`);
        }
    }

}
