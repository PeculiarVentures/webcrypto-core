import { OperationError } from "../errors";
import { ProviderCrypto } from "../provider";
import { KeyUsages } from "../types";

export class Pbkdf2Provider extends ProviderCrypto {

  public name = "PBKDF2";

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public usages: KeyUsages = ["deriveBits", "deriveKey"];

  public checkAlgorithmParams(algorithm: Pbkdf2Params) {
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as Algorithm, this.hashAlgorithms);

    // salt
    this.checkRequiredProperty(algorithm, "salt");
    if (!(algorithm.salt instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.salt))) {
      throw new TypeError("salt: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }

    // iterations
    this.checkRequiredProperty(algorithm, "iterations");
    if (typeof algorithm.iterations !== "number") {
      throw new TypeError("iterations: Is not a Number");
    }
    if (algorithm.iterations < 1) {
      throw new TypeError("iterations: Is less than 1");
    }
  }

  public checkImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]) {
    super.checkImportKey(format, keyData, algorithm, extractable, keyUsages);
    if (!extractable) {
      // If extractable is not false, then throw a SyntaxError
      throw new SyntaxError("extractable: Must be True");
    }
  }

}
