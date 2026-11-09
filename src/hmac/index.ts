import type { CryptoKey } from "../crypto_key";
import { ProviderCrypto } from "../provider";
import type { KeyUsages } from "../types";

export abstract class HmacProvider extends ProviderCrypto {
  public name = "HMAC";

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public usages: KeyUsages = ["sign", "verify"];

  /**
   * Returns default size in bits by hash algorithm name
   * @param algName Name of the hash algorithm
   */
  public getDefaultLength(algName: string): number {
    switch (algName.toUpperCase()) {
      case "SHA-1":
      case "SHA-256":
        return 512;
      case "SHA-384":
      case "SHA-512":
        return 1024;
      default:
        throw new Error(`Unknown algorithm name '${algName}'`);
    }
  }

  /** Returns the explicit HMAC key length, or the hash block size when omitted. */
  public override getKeyLength(algorithm: HmacKeyGenParams): number {
    this.checkImportParams(algorithm);
    if (algorithm.length === undefined) {
      return this.getDefaultLength((algorithm.hash as Algorithm).name);
    }
    if (!Number.isInteger(algorithm.length) || algorithm.length <= 0 || algorithm.length > 0xffffffff) {
      throw new TypeError("length: Must be a positive unsigned long");
    }
    return algorithm.length;
  }

  public override checkGenerateKeyParams(algorithm: HmacKeyGenParams): void {
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

  public override checkImportParams(algorithm: HmacImportParams): void {
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as Algorithm, this.hashAlgorithms);
  }

  public abstract override onGenerateKey(algorithm: HmacKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract override onExportKey(format: KeyFormat, key: CryptoKey, ...args: any[]): Promise<JsonWebKey | ArrayBuffer>;
  public abstract override onImportKey(
    format: KeyFormat,
    keyData: JsonWebKey | ArrayBuffer,
    algorithm: HmacImportParams,
    extractable: boolean,
    keyUsages: KeyUsage[],
    ...args: any[]
  ): Promise<CryptoKey>;
}
