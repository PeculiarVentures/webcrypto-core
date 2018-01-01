import { AlgorithmNames } from "../alg";
import { BaseCrypto } from "../base";
import { AlgorithmError } from "../error";

export const ShaAlgorithms = [AlgorithmNames.Sha1, AlgorithmNames.Sha256, AlgorithmNames.Sha384, AlgorithmNames.Sha512].join(" | ");

export class Sha extends BaseCrypto {

    public static checkAlgorithm(alg: AlgorithmIdentifier) {
        let alg2: Algorithm;
        if (typeof alg === "string") {
            alg2 = { name: alg };
        } else {
            alg2 = alg;
        }
        super.checkAlgorithm(alg2);
        switch (alg2.name.toUpperCase()) {
            case AlgorithmNames.Sha1:
            case AlgorithmNames.Sha256:
            case AlgorithmNames.Sha384:
            case AlgorithmNames.Sha512:
                break;
            default:
                throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg2.name, ShaAlgorithms);
        }
    }

    public static digest(algorithm: Algorithm, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithm(algorithm);
            resolve(undefined);
        });
    }
}
