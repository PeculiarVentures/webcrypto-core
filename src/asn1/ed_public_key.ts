import {
  AsnProp, AsnPropTypes, AsnType, AsnTypeTypes,
} from "@peculiar/asn1-schema";
import { IJsonConvertible } from "@peculiar/json-schema";
import * as encoding from "@peculiar/utils/encoding";
import * as bytes from "@peculiar/utils/bytes";

// RFC 8410
// https://datatracker.ietf.org/doc/html/rfc8410
//
// PublicKey ::= BIT STRING

@AsnType({ type: AsnTypeTypes.Choice })
export class EdPublicKey implements IJsonConvertible {
  @AsnProp({ type: AsnPropTypes.BitString })
  public value = new ArrayBuffer(0);

  constructor(value?: ArrayBuffer) {
    if (value) {
      this.value = value;
    }
  }

  public toJSON(): JsonWebKey {
    const json: JsonWebKey = { x: encoding.base64url.encode(this.value) };

    return json;
  }

  public fromJSON(json: any): this {
    if (!("x" in json)) {
      throw new Error("x: Missing required property");
    }

    this.value = bytes.toArrayBuffer(encoding.base64url.decode(json.x));

    return this;
  }
}
