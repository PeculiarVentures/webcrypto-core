import { KeyUsages } from "../types";
import { AesProvider } from "./base";

export class AesEcbProvider extends AesProvider {

  public readonly name = "AES-ECB";

  public usages: KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

}
