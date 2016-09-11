namespace webcrypto {

    export type AlgorithmIdentifier = Algorithm | string;

    export interface Algorithm {
        name: string;
        [key: string]: any;
    }

    export interface HashAlgorithm extends Algorithm {
        hash: Algorithm;
    }

    export type HashAlgorithmIdentifier = HashAlgorithm | string;

    export interface KeyAlgorithm {
        name: string;
    }

    export const AlgorithmNames = {
        RsaSSA: "RSASSA-PKCS1-v1_5",
        RsaPSS: "RSA-PSS",
        RsaOAEP: "RSA-OAEP",
        AesCTR: "AES-CTR",
        AesCMAC: "AES-CMAC",
        AesGCM: "AES-GCM",
        AesCBC: "AES-CBC",
        Sha1: "SHA-1",
        Sha256: "SHA-256",
        Sha384: "SHA-384",
        Sha512: "SHA-512",
        EcDSA: "ECDSA",
        EcDH: "ECDH"
    };

}