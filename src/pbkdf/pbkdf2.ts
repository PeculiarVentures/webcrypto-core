import type { CryptoKey } from "../crypto_key";
import { ProviderCrypto, type IProviderCheckOptions } from "../provider";
import { OperationError } from "../errors";
import type { KeyUsages } from "../types";

export abstract class Pbkdf2Provider extends ProviderCrypto {
  public name = "PBKDF2";

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public usages: KeyUsages = ["deriveBits", "deriveKey"];

  /** PBKDF2 imports the full secret when used as the target of deriveKey. */
  public override getKeyLength(_algorithm: Algorithm): null {
    return null;
  }

  public override checkAlgorithmParams(algorithm: Pbkdf2Params): void {
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

  public override checkImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): void {
    super.checkImportKey(format, keyData, algorithm, extractable, keyUsages, ...args);
    if (extractable) {
      // If extractable is not false, then throw a SyntaxError
      throw new SyntaxError("extractable: Must be 'false'");
    }
  }

  public override checkDeriveBits(algorithm: Pbkdf2Params, baseKey: CryptoKey, length: number | null, options: IProviderCheckOptions = {}, ...args: any[]): void {
    super.checkDeriveBits(algorithm, baseKey, length, options, ...args);
    if (length === null) {
      throw new OperationError("length: Must not be null");
    }
  }

  public abstract override onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract override onDeriveBits(algorithm: Pbkdf2Params, baseKey: CryptoKey, length: number, ...args: any[]): Promise<ArrayBuffer>;
}
