import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { BufferSourceConverter } from "pvtsutils";
import { AsnIntegerWithoutPaddingConverter } from "./converters";

// RFC 3279
// https://tools.ietf.org/html/rfc3279#section-2.2.3
//
// ECDSA-Sig-Value ::= SEQUENCE {
//   r  INTEGER,
//   s  INTEGER
// }



export class EcDsaSignature {

  public static fromWebCryptoSignature(value: BufferSource): EcDsaSignature {
    const wcSignature = BufferSourceConverter.toUint8Array(value);
    const pointSize = wcSignature.byteLength / 2;
    const ecSignature = new this();
    ecSignature.r = ecSignature.removePadding(wcSignature.slice(0, pointSize));
    ecSignature.s = ecSignature.removePadding(wcSignature.slice(pointSize, pointSize * 2));
    return ecSignature;
  }

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerWithoutPaddingConverter })
  public r = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerWithoutPaddingConverter })
  public s = new ArrayBuffer(0);

  public toWebCryptoSignature(pointSize?: number) {
    pointSize = this.getPointSize();
    const r = this.addPadding(pointSize, BufferSourceConverter.toUint8Array(this.r));
    const s = this.addPadding(pointSize, BufferSourceConverter.toUint8Array(this.s));

    const wcSignature = new Uint8Array(r.byteLength + s.byteLength);
    wcSignature.set(r, 0);
    wcSignature.set(s, r.length);
    return wcSignature.buffer;
  }

  private getPointSize(): number {
    // tslint:disable-next-line: no-bitwise
    const size = Math.max(this.r.byteLength, this.s.byteLength);
    switch (size) {
      case 31:
      case 32:
        return 32;
      case 47:
      case 48:
        return 48;
      case 65:
      case 66:
        return 66;
    }
    throw new Error("Unsupported EC point size");
  }

  private addPadding(pointSize: number, bytes: BufferSource) {
    const res = new Uint8Array(pointSize);
    const uint8Array = BufferSourceConverter.toUint8Array(bytes);
    res.set(uint8Array, pointSize - uint8Array.length);
    return res;
  }

  private removePadding(bytes: BufferSource) {
    const uint8Array = BufferSourceConverter.toUint8Array(bytes);
    for (let i = 0; i < uint8Array.length; i++) {
      if (!uint8Array[i]) {
        continue;
      }
      return uint8Array.slice(i);
    }
    return new Uint8Array(0);
  }

}
