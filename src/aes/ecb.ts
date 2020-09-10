import { KeyUsages } from "../types";
import { AesProvider } from "./base";

export abstract class AesEcbProvider extends AesProvider {

  public readonly name = "AES-ECB";

  public usages: KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  public abstract onEncrypt(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract onDecrypt(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
