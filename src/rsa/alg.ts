namespace webcrypto.rsa {

    export interface RsaKeyGenParams extends Algorithm {
        /**
         * The length, in bits, of the RSA modulus 
         * 
         * @type {number}
         */
        modulusLength: number;
        /**
         * The RSA public exponent
         * 
         * @type {Uint8Array}
         */
        publicExponent: Uint8Array;
    }

    export interface RsaHashedKeyGenParams extends RsaKeyGenParams, HashAlgorithm {}

    export interface RsaKeyAlgorithm extends KeyAlgorithm {
        /**
         * The length, in bits, of the RSA modulus
         * 
         * @type {number}
         */
        modulusLength: number;
        /**
         * The RSA public exponent
         * 
         * @type {Uint8Array}
         */
        publicExponent: Uint8Array;
    }

    export interface RsaHashedKeyAlgorithm extends RsaKeyAlgorithm {
        /**
         * The hash algorithm that is used with this key
         * 
         * @type {KeyAlgorithm}
         */
        hash: KeyAlgorithm;
    }

    export interface RsaHashedImportParams extends HashAlgorithm { }

    export interface RsaPssParams extends Algorithm {
        /**
         * The desired length of the random salt
         * 
         * @type {number}
         */
        saltLength: number;
    }

    export interface RsaOaepParams extends Algorithm {
        /**
         * The optional label/application data to associate with the message
         * 
         * @type {Uint8Array}
         */
        label: Uint8Array;
    }

}