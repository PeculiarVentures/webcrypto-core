import { describe, it, expect } from "vitest";
import { JsonParser } from "@peculiar/json-schema";
import * as encoding from "@peculiar/utils/encoding";
import { EcPublicKey, EdPublicKey, RsaPublicKey } from "../../asn1";
import { JsonBase64UrlArrayBufferConverter } from "./base64_url";

const fromJSON = (value: string) => JsonBase64UrlArrayBufferConverter.fromJSON(value, {});
const toJSON = (value: ArrayBuffer) => JsonBase64UrlArrayBufferConverter.toJSON(value, {});

// JWK members are base64url without padding (RFC 7515, section 2). These
// cases pin the decoder behavior that 1.x already had, so a change in
// @peculiar/utils shows up here.
describe("JsonBase64UrlArrayBufferConverter", () => {
  it("decodes unpadded base64url", () => {
    expect(encoding.hex.encode(fromJSON("AQAB"))).toBe("010001");
    expect(encoding.hex.encode(fromJSON("-_8"))).toBe("fbff");
  });

  it("encodes without padding", () => {
    expect(toJSON(new Uint8Array([0xfb, 0xff]).buffer)).toBe("-_8");
  });

  it("decodes an empty string to an empty buffer", () => {
    expect(fromJSON("").byteLength).toBe(0);
  });

  it("ignores whitespace", () => {
    expect(encoding.hex.encode(fromJSON(" AQ\nAB "))).toBe("010001");
  });

  it("rejects padded base64url", () => {
    expect(() => fromJSON("-_8=")).toThrow(TypeError);
    expect(() => fromJSON("AQ==")).toThrow(TypeError);
  });

  it("rejects base64 characters that are not base64url", () => {
    expect(() => fromJSON("+/8")).toThrow(TypeError);
  });

  it("rejects invalid characters", () => {
    expect(() => fromJSON("AQ.B")).toThrow(TypeError);
    expect(() => fromJSON("AQ*B")).toThrow(TypeError);
  });
});

describe("JWK import", () => {
  // P-256 public key from RFC 7517, appendix A.1
  const ecJwk = {
    kty: "EC",
    crv: "P-256",
    x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  };

  it("imports an EC public key", () => {
    const key = new EcPublicKey().fromJSON(ecJwk);
    expect(key.value.byteLength).toBe(65);
  });

  it("rejects an EC public key with padded coordinates", () => {
    expect(() => new EcPublicKey().fromJSON({ ...ecJwk, x: `${ecJwk.x}=` })).toThrow(TypeError);
  });

  it("rejects an EC public key with invalid characters", () => {
    expect(() => new EcPublicKey().fromJSON({ ...ecJwk, y: `+${ecJwk.y.slice(1)}` })).toThrow(TypeError);
  });

  it("rejects an Ed25519 public key with padding", () => {
    const x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    expect(new EdPublicKey().fromJSON({ x }).value.byteLength).toBe(32);
    expect(() => new EdPublicKey().fromJSON({ x: `${x}=` })).toThrow(TypeError);
  });

  it("rejects an RSA public key with a padded exponent", () => {
    const n =
      "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw";
    const key = JsonParser.fromJSON({ n, e: "AQAB" }, { targetSchema: RsaPublicKey });
    expect(key.publicExponent.byteLength).toBe(3);
    expect(() => JsonParser.fromJSON({ n, e: "AQAB=" }, { targetSchema: RsaPublicKey })).toThrow();
    expect(() => JsonParser.fromJSON({ n: `${n}==`, e: "AQAB" }, { targetSchema: RsaPublicKey })).toThrow();
  });
});
