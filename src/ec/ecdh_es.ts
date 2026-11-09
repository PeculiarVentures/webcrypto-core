import { EcdhProvider } from "./ecdh";
import type { IProviderCheckOptions } from "../provider";

const secretLengths: Record<string, number> = { X25519: 256, X448: 448 };

export abstract class EcdhEsProvider extends EcdhProvider {
  public override readonly name: string = "ECDH-ES";

  public override namedCurves = ["X25519", "X448"];

  /** Resolves null to the full secret length for existing X25519/X448 backends. */
  public override getDeriveBitsLength(algorithm: Algorithm, baseKey: globalThis.CryptoKey, length: number | null, options?: IProviderCheckOptions): number | null {
    if (length === null) {
      const namedCurve = (baseKey.algorithm as EcKeyAlgorithm).namedCurve;
      length = typeof namedCurve === "string" ? (secretLengths[namedCurve.toUpperCase()] ?? null) : null;
    }
    return super.getDeriveBitsLength(algorithm, baseKey, length, options);
  }

  /** Rejects missing curve metadata during key validation, before calling the backend. */
  public override checkCryptoKey(key: globalThis.CryptoKey, keyUsage?: KeyUsage): void {
    super.checkCryptoKey(key, keyUsage);
    const namedCurve = (key.algorithm as EcKeyAlgorithm).namedCurve;
    if (typeof namedCurve !== "string" || !namedCurve.length) {
      throw new DOMException("Key algorithm must specify a named curve", "InvalidAccessError");
    }
  }
}
