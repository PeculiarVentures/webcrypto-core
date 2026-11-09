import { EcdhProvider } from "./ecdh";
import type { IProviderCheckOptions } from "../provider";

const secretLengths: Record<string, number> = { X25519: 256, X448: 448 };

export abstract class EcdhEsProvider extends EcdhProvider {
  public override readonly name: string = "ECDH-ES";

  public override namedCurves = ["X25519", "X448"];

  /** Resolves null to the full secret length for existing X25519/X448 backends. */
  public override async deriveBits(algorithm: Algorithm, baseKey: globalThis.CryptoKey, length: number | null, options?: IProviderCheckOptions, ...args: any[]): Promise<ArrayBuffer> {
    if (length === null) {
      length = secretLengths[(baseKey.algorithm as EcKeyAlgorithm).namedCurve.toUpperCase()] ?? null;
    }
    return super.deriveBits(algorithm, baseKey, length, options, ...args);
  }
}
