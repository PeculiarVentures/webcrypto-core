import { AlgorithmNames } from "../alg";
import { BaseCrypto } from "../base";
import { AlgorithmError } from "../error";

export const ShaAlgorithms = [AlgorithmNames.Sha1, AlgorithmNames.Sha256, AlgorithmNames.Sha384, AlgorithmNames.Sha512].join(" | ");

export class Sha extends BaseCrypto {

    static checkAlgorithm(alg: Algorithm) {
        let _alg: Algorithm;
        if (typeof alg === "string")
            _alg = { name: alg };
        else
            _alg = alg;
        super.checkAlgorithm(alg);
        switch (_alg.name.toUpperCase()) {
            case AlgorithmNames.Sha1:
            case AlgorithmNames.Sha256:
            case AlgorithmNames.Sha384:
            case AlgorithmNames.Sha512:
                break;
            default:
                throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, _alg.name, ShaAlgorithms);
        }
    }

    static digest(algorithm: Algorithm, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkAlgorithm(algorithm);
            resolve(undefined);
        });
    }
}