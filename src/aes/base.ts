import { ProviderCrypto } from "../provider";

export abstract class AesProvider extends ProviderCrypto {

  public checkGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]) {
    super.checkGenerateKey.apply(this, arguments);

    // check key gen params
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not a Number");
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

}
