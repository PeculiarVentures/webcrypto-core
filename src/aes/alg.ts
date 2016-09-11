namespace webcrypto.aes {

    export interface AesCtrParams extends Algorithm {
        /**
         * The initial value of the counter block. counter MUST be 16 bytes
         * (the AES block size). The counter bits are the rightmost length
         * bits of the counter block. The rest of the counter block is for
         * the nonce. The counter bits are incremented using the standard
         * incrementing function specified in NIST SP 800-38A Appendix B.1extends
         * the counter bits are interpreted as a big-endian integer and
         * incremented by one. 
         * 
         * @type {ArrayBufferView}
         */
        counter: ArrayBufferView;
        /**
         * The length, in bits, of the rightmost part of the counter block
         * that is incremented. 
         * 
         * @type {number}
         */
        length: number;
    }

    export interface AesKeyAlgorithm extends KeyAlgorithm {
        /**
         * The length, in bits, of the key.
         * 
         * @type {number}
         */
        length: number;
    }

    export interface AesKeyGenParams extends Algorithm {
        /**
         * The length, in bits, of the key.
         * 
         * @type {number}
         */
        length: number;
    }

    export interface AesDerivedKeyParams extends Algorithm {
        /**
         * The length, in bits, of the key.
         * 
         * @type {number}
         */
        length: number;
    }

    export interface AesCbcParams extends Algorithm {
        /**
         * The initialization vector. MUST be 16 bytes.
         * 
         * @type {ArrayBufferView}
         */
        iv: ArrayBufferView;
    };

    export interface AesCmacParams extends Algorithm {
        /**
         * The length, in bits, of the MAC.
         * 
         * @type {number}
         */
        length: number;
    };

    export interface AesGcmParams extends Algorithm {
        /**
         * The initialization vector to use. May be up to 2^64-1 bytes long.
         * 
         * @type {ArrayBufferView}
         */
        iv: ArrayBufferView;
        /**
         * The additional authentication data to include.
         * 
         * @type {ArrayBufferView}
         */
        additionalData: ArrayBufferView;
        /**
         * The desired length of the authentication tag. May be 0 - 128.
         * 
         * @type {number}
         */
        tagLength: number;
    }

    export interface AesCfbParams extends Algorithm {
        /**
         * The initialization vector. MUST be 16 bytes.
         * 
         * @type {ArrayBufferView}
         */
        iv: ArrayBufferView;
    };

}