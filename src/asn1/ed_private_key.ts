import {
  AsnProp, AsnPropTypes, AsnType, AsnTypeTypes,
} from "@peculiar/asn1-schema";
import { IJsonConvertible } from "@peculiar/json-schema";
import * as encoding from "@peculiar/utils/encoding";
import * as bytes from "@peculiar/utils/bytes";

@AsnType({ type: AsnTypeTypes.Choice })
export class EdPrivateKey implements IJsonConvertible {
  @AsnProp({ type: AsnPropTypes.OctetString })
  public value = new ArrayBuffer(0);

  public fromJSON(json: any): this {
    if (!json.d) {
      throw new Error("d: Missing required property");
    }
    this.value = bytes.toArrayBuffer(encoding.base64url.decode(json.d));

    return this;
  }

  public toJSON(): JsonWebKey {
    const jwk: JsonWebKey = { d: encoding.base64url.encode(this.value) };

    return jwk;
  }
}
