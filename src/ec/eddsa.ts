import { ProviderKeyUsages } from "../types";
import { EllipticProvider } from "./base";

export class EddsaProvider extends EllipticProvider {

  public readonly name = "EDDSA";

  public readonly namedCurves = ["CURVE25519"];

  public usages: ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };
}
