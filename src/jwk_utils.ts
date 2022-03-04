import { Convert } from "pvtsutils";

const REQUIRED_FIELDS = ["crv", "e", "k", "kty", "n", "x", "y"];

export class JwkUtils {

  public static async thumbprint(hash: AlgorithmIdentifier, jwk: JsonWebKey, crypto: Crypto): Promise<ArrayBuffer> {
    const data = this.format(jwk, true);

    return crypto.subtle.digest(hash, Convert.FromBinary(JSON.stringify(data)));
  }

  public static format(jwk: JsonWebKey, remove = false): JsonWebKey {
    let res = Object.entries(jwk);
    if (remove) {
      res = res.filter(o => REQUIRED_FIELDS.includes(o[0]));
    }

    res = res.sort(([keyA], [keyB]) =>
      keyA > keyB ? 1 : keyA < keyB ? -1 : 0);

    return Object.fromEntries(res) as JsonWebKey;
  }

}
