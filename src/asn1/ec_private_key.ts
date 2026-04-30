import {
  AsnIntegerConverter, AsnProp, AsnPropTypes, AsnSerializer,
} from "@peculiar/asn1-schema";
import { IJsonConvertible } from "@peculiar/json-schema";
import * as encoding from "@peculiar/utils/encoding";
import * as bytes from "@peculiar/utils/bytes";
import { EcPublicKey } from "./ec_public_key";

// RFC 5915
// https://tools.ietf.org/html/rfc5915#section-3
//
// ECPrivateKey ::= SEQUENCE {
//   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//   privateKey     OCTET STRING,
//   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
//   publicKey  [1] BIT STRING OPTIONAL
// }

export class EcPrivateKey implements IJsonConvertible {
  @AsnProp({
    type: AsnPropTypes.Integer, converter: AsnIntegerConverter,
  })
  public version = 1;

  @AsnProp({ type: AsnPropTypes.OctetString })
  public privateKey = new ArrayBuffer(0);

  @AsnProp({
    context: 0, type: AsnPropTypes.Any, optional: true,
  })
  public parameters?: ArrayBuffer;

  @AsnProp({
    context: 1, type: AsnPropTypes.BitString, optional: true,
  })
  public publicKey?: ArrayBuffer;

  public fromJSON(json: any): this {
    if (!("d" in json)) {
      throw new Error("d: Missing required property");
    }
    this.privateKey = bytes.toArrayBuffer(encoding.base64url.decode(json.d));

    if ("x" in json) {
      const publicKey = new EcPublicKey();
      publicKey.fromJSON(json);

      const asn = AsnSerializer.toASN(publicKey);
      if ("valueHex" in asn.valueBlock) {
        this.publicKey = asn.valueBlock.valueHex;
      }
    }

    return this;
  }

  public toJSON(): JsonWebKey {
    const jwk: JsonWebKey = {};
    jwk.d = encoding.base64url.encode(this.privateKey);
    if (this.publicKey) {
      Object.assign(jwk, new EcPublicKey(this.publicKey).toJSON());
    }
    return jwk;
  }
}
