import { ProviderCrypto } from "../provider";
import { KeyUsages } from "../types";
import { BufferSourceConverter } from "../utils";

export abstract class HkdfProvider extends ProviderCrypto {

  public name = "HKDF";
  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
  public usages: KeyUsages = ["deriveKey", "deriveBits"];

  public checkAlgorithmParams(algorithm: HkdfParams) {
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as Algorithm, this.hashAlgorithms);

    // salt
    this.checkRequiredProperty(algorithm, "salt");
    if (!BufferSourceConverter.isBufferSource(algorithm.salt)) {
      throw new TypeError("salt: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }

    // info
    this.checkRequiredProperty(algorithm, "info");
    if (!BufferSourceConverter.isBufferSource(algorithm.info)) {
      throw new TypeError("salt: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
  }

  public checkImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]) {
    super.checkImportKey(format, keyData, algorithm, extractable, keyUsages);
    if (extractable) {
      // If extractable is not false, then throw a SyntaxError
      throw new SyntaxError("extractable: Must be False");
    }
  }

  public abstract onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
  public abstract onDeriveBits(algorithm: Pbkdf2Params, baseKey: CryptoKey, length: number): Promise<ArrayBuffer>;

}
