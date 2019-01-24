import { KeyUsages } from "../types";
import { AesProvider } from "./base";

export class AesKwProvider extends AesProvider {

  public readonly name = "AES-KW";

  public usages: KeyUsages = ["wrapKey", "unwrapKey"];

}
