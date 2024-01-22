import { CryptoKey } from "../crypto_key";
import { ProviderCrypto } from "../provider";
import { KeyUsages } from "../types";

export abstract class Pbkdf2Provider extends ProviderCrypto {

  public name = "PBKDF2";

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public usages: KeyUsages = ["deriveBits", "deriveKey"];

  public checkAlgorithmParams(algorithm: Pbkdf2Params): void {
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

  public checkImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): void {
    super.checkImportKey(format, keyData, algorithm, extractable, keyUsages, ...args);
    if (extractable) {
      // If extractable is not false, then throw a SyntaxError
      throw new SyntaxError("extractable: Must be 'false'");
    }
  }

  public abstract onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract onDeriveBits(algorithm: Pbkdf2Params, baseKey: CryptoKey, length: number, ...args: any[]): Promise<ArrayBuffer>;

}
