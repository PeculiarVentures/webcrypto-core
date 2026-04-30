import {
  AsnProp, AsnPropTypes, AsnType, AsnTypeTypes,
} from "@peculiar/asn1-schema";
import { IJsonConvertible } from "@peculiar/json-schema";
import * as bytes from "@peculiar/utils/bytes";
import * as encoding from "@peculiar/utils/encoding";
import { CryptoError } from "../errors";

// RFC 5480
// https://tools.ietf.org/html/rfc5480#section-2.2
//
// ECPoint ::= OCTET STRING

@AsnType({ type: AsnTypeTypes.Choice })
export class EcPublicKey implements IJsonConvertible {
  @AsnProp({ type: AsnPropTypes.OctetString })
  public value = new ArrayBuffer(0);

  constructor(value?: ArrayBuffer) {
    if (value) {
      this.value = value;
    }
  }

  public toJSON(): JsonWebKey {
    let bytes = new Uint8Array(this.value);

    if (bytes[0] !== 0x04) {
      throw new CryptoError("Wrong ECPoint. Current version supports only Uncompressed (0x04) point");
    }

    bytes = new Uint8Array(this.value.slice(1));
    const size = bytes.length / 2;

    const offset = 0;
    const json = {
      x: encoding.base64url.encode(bytes.buffer.slice(offset, offset + size)),
      y: encoding.base64url.encode(bytes.buffer.slice(offset + size, offset + size + size)),
    };

    return json;
  }

  public fromJSON(json: any): this {
    if (!("x" in json)) {
      throw new Error("x: Missing required property");
    }
    if (!("y" in json)) {
      throw new Error("y: Missing required property");
    }

    const x = encoding.base64url.decode(json.x);
    const y = encoding.base64url.decode(json.y);

    const value = bytes.concat(
      new Uint8Array([0x04]).buffer, // uncompressed bit
      x,
      y,
    );

    this.value = bytes.toArrayBuffer(value);

    return this;
  }
}
