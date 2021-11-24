import { Convert } from "pvtsutils";
import { CryptoKey } from "../crypto_key";
import { CryptoKeyPair } from "../crypto_key_pair";
import { ProviderCrypto } from "../provider";

export abstract class RsaProvider extends ProviderCrypto {

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public checkGenerateKeyParams(algorithm: RsaHashedKeyGenParams) {
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
    if (algorithm.modulusLength % 8
      || algorithm.modulusLength < 256
      || algorithm.modulusLength > 16384) {
      throw new TypeError("The modulus length must be a multiple of 8 bits and >= 256 and <= 16384");
    }
  }

  public checkImportParams(algorithm: RsaHashedImportParams) {
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as Algorithm, this.hashAlgorithms);
  }

  public abstract onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKeyPair>;
  public abstract onExportKey(format: KeyFormat, key: CryptoKey, ...args: any[]): Promise<JsonWebKey | ArrayBuffer>;
  public abstract onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;

}
