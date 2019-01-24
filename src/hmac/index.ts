import { OperationError } from "../errors";
import { ProviderCrypto } from "../provider";
import { KeyUsages } from "../types";

export class HmacProvider extends ProviderCrypto {

  public name = "HMAC";

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public usages: KeyUsages = ["sign", "verify"];

  /**
   * Returns default size in bits by hash algorithm name
   * @param algName Name of the hash algorithm
   */
  public getDefaultLength(algName: string) {
    switch (algName.toUpperCase()) {
      case "SHA-1":
        return 160;
      case "SHA-256":
        return 256;
      case "SHA-384":
        return 384;
      case "SHA-521":
        return 521;
      default:
        throw new Error(`Unknown algorithm name '${algName}'`);
    }
  }

  public checkGenerateKey(algorithm: HmacKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]) {
    super.checkGenerateKey.apply(this, arguments);

    // hash
    this.checkHashAlgorithm(algorithm.hash as Algorithm, this.hashAlgorithms);

    // length
    if ("length" in algorithm) {
      if (typeof algorithm.length !== "number") {
        throw new TypeError("length: Is not a Number");
      }
      if (algorithm.length < 8) {
        throw new OperationError("length: Is less than 8 bits");
      }
    }
  }

}
