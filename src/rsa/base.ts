import { Convert } from "pvtsutils";
import { AlgorithmError } from "../errors";
import { ProviderCrypto } from "../provider";
import { HashedAlgorithm } from "../types";

export abstract class RsaProvider extends ProviderCrypto {

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public checkGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]) {
    super.checkGenerateKey.apply(this, arguments);

    // check key gen params
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as Algorithm, this.hashAlgorithms);
    // public exponent
    this.checkRequiredProperty(algorithm, "publicExponent");
    if (!(algorithm.publicExponent && algorithm.publicExponent instanceof Uint8Array)) {
      throw new TypeError("publicExponent: Missing or not a Uint8Array");
    }
    const publicExponent = Convert.ToBase64(algorithm.publicExponent);
    if (!(publicExponent === "Aw==" || publicExponent === "AQAB")) {
      throw new TypeError("publicExponent: Must be [3] or [1,0,1]");
    }
    // modulus length
    this.checkRequiredProperty(algorithm, "modulusLength");
    switch (algorithm.modulusLength) {
      case 1024:
      case 2048:
      case 4096:
      break;
      default:
        throw new TypeError("modulusLength: Must be 1024, 2048, or 4096");
    }
  }

}
