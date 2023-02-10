import * as assert from "assert";
import { AsnConvert } from "@peculiar/asn1-schema";
import { JsonSerializer } from "@peculiar/json-schema";
import { Convert } from "pvtsutils";
import { EcPrivateKey, EcPublicKey, PrivateKeyInfo, PublicKeyInfo } from "../../src/asn1";

context("ECDSA keys", () => {

  it("Private key", () => {
    const hex = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042020c42828fe6dccb3f01dced6d40db1a1d9f7829e502b2de4a2243def60dfda4fa14403420004578e6cdfba9fba0b8180ebd3c9176695e4054179be0c8ce03ae93bcd0c8695407e6426d13c2aa20d2f8ced0224249d9a29c3738cd2a535eac51051e05dfd6406";
    const raw = Buffer.from(hex, "hex");

    const pki = AsnConvert.parse(raw, PrivateKeyInfo);
    assert.strictEqual(pki.privateKeyAlgorithm.algorithm, "1.2.840.10045.2.1");
    const privateKey = AsnConvert.parse(pki.privateKey, EcPrivateKey);

    const json = JsonSerializer.toJSON(privateKey);
    assert.deepStrictEqual(json, {
      d: "IMQoKP5tzLPwHc7W1A2xodn3gp5QKy3koiQ972Df2k8",
      x: "V45s37qfuguBgOvTyRdmleQFQXm-DIzgOuk7zQyGlUA",
      y: "fmQm0Twqog0vjO0CJCSdminDc4zSpTXqxRBR4F39ZAY",
    });

    const fromJson = new EcPrivateKey();
    fromJson.fromJSON(json);
    const raw2 = AsnConvert.serialize(fromJson);
    assert.strictEqual(Convert.ToHex(raw2), "306b020101042020c42828fe6dccb3f01dced6d40db1a1d9f7829e502b2de4a2243def60dfda4fa14403420004578e6cdfba9fba0b8180ebd3c9176695e4054179be0c8ce03ae93bcd0c8695407e6426d13c2aa20d2f8ced0224249d9a29c3738cd2a535eac51051e05dfd6406");
  });

  it("Public key", () => {
    const hex = "3059301306072a8648ce3d020106082a8648ce3d0301070342000420cc0f60fe5fc30f889cbf4a5cd9eb7a632682572b62856098e29b34c288f39014f2271a29221e6f9e849a95da99edcc7e3826cddec2701aafb9479cae146ee2";
    const raw = Convert.FromHex(hex);

    const pki = AsnConvert.parse(raw, PublicKeyInfo);
    assert.strictEqual(pki.publicKeyAlgorithm.algorithm, "1.2.840.10045.2.1");
    const publicKey = new EcPublicKey(pki.publicKey);

    const json = JsonSerializer.toJSON(publicKey);
    assert.deepStrictEqual(json, {
      x: "IMwPYP5fww-InL9KXNnremMmglcrYoVgmOKbNMKI85A",
      y: "FPInGikiHm-ehJqV2pntzH44Js3ewnAar7lHnK4UbuI"
    });

    const fromJson = new EcPublicKey();
    fromJson.fromJSON(json);
    const raw2 = AsnConvert.serialize(fromJson);
    assert.strictEqual(Convert.ToHex(raw2), "04410420cc0f60fe5fc30f889cbf4a5cd9eb7a632682572b62856098e29b34c288f39014f2271a29221e6f9e849a95da99edcc7e3826cddec2701aafb9479cae146ee2");
  });

});
