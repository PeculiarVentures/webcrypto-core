import { ProviderCrypto } from "../provider";
import type { CryptoKey } from "../crypto_key";
import { OperationError } from "../errors";

export abstract class AesProvider extends ProviderCrypto {
  public override checkGenerateKeyParams(algorithm: AesKeyGenParams): void {
    // length
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not of type Number");
    }
    switch (algorithm.length) {
      case 128:
      case 192:
      case 256:
        break;
      default:
        throw new TypeError("length: Must be 128, 192, or 256");
    }
  }

  public override checkDerivedKeyParams(algorithm: AesKeyGenParams): void {
    this.getKeyLength(algorithm);
  }

  /** Returns the requested AES key length in bits. */
  public override getKeyLength(algorithm: AesKeyGenParams): number {
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not of type Number");
    }
    if (algorithm.length !== 128 && algorithm.length !== 192 && algorithm.length !== 256) {
      throw new OperationError("length: Must be 128, 192, or 256");
    }
    return algorithm.length;
  }

  public abstract override onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract override onExportKey(format: KeyFormat, key: CryptoKey, ...args: any[]): Promise<JsonWebKey | ArrayBuffer>;
  public abstract override onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;
}
