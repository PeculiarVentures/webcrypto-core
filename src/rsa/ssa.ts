import { ProviderKeyUsages } from "../types";
import { RsaProvider } from "./base";

export class RsaSsaProvider extends RsaProvider {

  public readonly name = "RSASSA-PKCS1-v1_5";

  public usages: ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };

}
