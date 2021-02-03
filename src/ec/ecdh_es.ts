import { EcdhProvider } from "./ecdh";

export abstract class EcdhEsProvider extends EcdhProvider {
  public readonly name: string = "ECDH-ES";

  public namedCurves = ["X25519", "X448"];
}