namespace webcrypto.ec {

    export interface EcdsaParams extends Algorithm, HashAlgorithm { }

    /**
     * "P-256"
     * NIST recommended curve P-256, also known as secp256r1.
     * "P-384"
     * NIST recommended curve P-384, also known as secp384r1.
     * "P-521"
     * NIST recommended curve P-521, also known as secp521r1.
     */
    export type NamedCurve = string;

    export interface EcKeyGenParams extends Algorithm {
        /**
         * A named curve
         * 
         * @type {NamedCurve}
         */
        namedCurve: NamedCurve;
    }

    export interface EcKeyAlgorithm extends KeyAlgorithm {
        /**
         * The named curve that the key uses
         * 
         * @type {NamedCurve}
         */
        namedCurve: NamedCurve;
    }


    export interface EcKeyImportParams extends Algorithm {
        /**
         * A named curve
         * 
         * @type {NamedCurve}
         */
        namedCurve: NamedCurve;
    }

    export interface EcdhKeyDeriveParams extends Algorithm {
        /**
         * The peer's EC public key
         * 
         * @type {CryptoKey}
         */
        public: CryptoKey;
    }

    export interface EcJWKPublicKey extends JWK {
        crv: string;
        ext: boolean;
        x: string;
        y: string;
        key_ops: string[];
        kty: string;
    }

    export interface EcJWKPrivateKey extends EcJWKPublicKey {
        d: string;
    }

}