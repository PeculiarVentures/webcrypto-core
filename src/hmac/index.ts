import { OperationError } from "../errors";
import { ProviderCrypto } from "../provider";
import { KeyUsages } from "../types";

export abstract class HmacProvider extends ProviderCrypto {

  public name = "HMAC";

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public usages: KeyUsages = ["sign", "verify"];

  /**
   * Returns default size in bits by hash algorithm name
   * @param algName Name of the hash algorithm
   */
  public getDefaultLength(algName: string) {
    switch (algName.toUpperCase()) {
      // Chrome, Safari and Firefox returns 512
      case "SHA-1":
      case "SHA-256":
      case "SHA-384":
      case "SHA-512":
        return 512;
      default:
        throw new Error(`Unknown algorithm name '${algName}'`);
    }
  }

  public checkGenerateKeyParams(algorithm: HmacKeyGenParams) {
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as Algorithm, this.hashAlgorithms);

    // length
    if ("length" in algorithm) {
      if (typeof algorithm.length !== "number") {
        throw new TypeError("length: Is not a Number");
      }
      if (algorithm.length < 1) {
        throw new RangeError("length: Number is out of range");
      }
    }
  }

  public checkImportParams(algorithm: HmacImportParams) {
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as Algorithm, this.hashAlgorithms);
  }

  public abstract onGenerateKey(algorithm: HmacKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract onExportKey(format: KeyFormat, key: CryptoKey, ...args: any[]): Promise<JsonWebKey | ArrayBuffer>;
  public abstract onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: HmacImportParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;

}
