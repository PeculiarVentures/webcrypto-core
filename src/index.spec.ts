import { describe, it, expect } from "vitest";
import { AsnConvert } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "./index";

describe("public API", () => {
  it("exports the 1.x runtime names except BufferSourceConverter", () => {
    expect(Object.keys(core).sort()).toEqual([
      "AesCbcProvider",
      "AesCmacProvider",
      "AesCtrProvider",
      "AesEcbProvider",
      "AesGcmProvider",
      "AesKwProvider",
      "AesProvider",
      "AlgorithmError",
      "Crypto",
      "CryptoError",
      "CryptoKey",
      "DesProvider",
      "EcCurves",
      "EcUtils",
      "EcdhEsProvider",
      "EcdhProvider",
      "EcdsaProvider",
      "Ed25519Provider",
      "EdDsaProvider",
      "EllipticProvider",
      "HkdfProvider",
      "HmacProvider",
      "JwkUtils",
      "OperationError",
      "Pbkdf2Provider",
      "PemConverter",
      "ProviderCrypto",
      "ProviderStorage",
      "RequiredPropertyError",
      "RsaOaepProvider",
      "RsaProvider",
      "RsaPssProvider",
      "RsaSsaProvider",
      "Shake128Provider",
      "Shake256Provider",
      "ShakeProvider",
      "SubtleCrypto",
      "UnsupportedOperationError",
      "X25519Provider",
      "asn1",
      "isJWK",
      "json",
    ]);
  });

  it("dispatches to a registered provider", async () => {
    class TestDigest extends core.ProviderCrypto {
      public name = "TEST-DIGEST";
      public usages = [];
      public override async onDigest(_algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
        return new Uint8Array(data).reverse().buffer;
      }
    }
    const subtle = new core.SubtleCrypto();
    subtle.providers.set(new TestDigest());

    const digest = await subtle.digest("test-digest", new Uint8Array([1, 2, 3]));
    expect(new Uint8Array(digest)).toEqual(new Uint8Array([3, 2, 1]));
    await expect(subtle.digest("SHA-1", new Uint8Array(0))).rejects.toThrow(core.AlgorithmError);
  });

  it("validates provider parameters", () => {
    // Only the check* methods run here, so the abstract on* methods stay unimplemented.
    abstract class TestEcdsa extends core.EcdsaProvider {}
    const provider = new (TestEcdsa as unknown as new () => core.EcdsaProvider)();
    const algorithm = { name: "ECDSA", namedCurve: "P-256" } as EcKeyGenParams;
    expect(() => provider.checkGenerateKey(algorithm, false, ["sign", "verify"])).not.toThrow();
    expect(() => provider.checkGenerateKey({ ...algorithm, namedCurve: "P-2" } as EcKeyGenParams, false, ["sign"])).toThrow(core.OperationError);
    expect(() => provider.checkGenerateKey(algorithm, false, ["encrypt"])).toThrow(TypeError);
  });

  it("round-trips keys through the asn1 and json namespaces", () => {
    const jwk = {
      n: "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
      e: "AQAB",
    };
    const key = JsonParser.fromJSON(jwk, { targetSchema: core.asn1.RsaPublicKey });
    const der = AsnConvert.serialize(key);
    const parsed = AsnConvert.parse(der, core.asn1.RsaPublicKey);
    expect(JsonSerializer.toJSON(parsed)).toEqual(jwk);
    expect(core.EcCurves.get("P-256").size).toBe(256);
    expect(core.json.converters.JsonBase64UrlArrayBufferConverter).toBeDefined();
  });
});
