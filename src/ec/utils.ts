import type { BufferSourceLike, StrictBufferSource } from "@peculiar/utils/bytes";
import * as bytes from "@peculiar/utils/bytes";

interface EcPoint {
  x: StrictBufferSource;
  y: StrictBufferSource;
}

interface EcSignaturePoint {
  r: StrictBufferSource;
  s: StrictBufferSource;
}

export class EcUtils {
  /**
   * Decodes ANSI X9.62 encoded point
   * @note Used by SunPKCS11 and SunJSSE
   * @param data ANSI X9.62 encoded point
   * @param pointSize Size of the point in bits
   * @returns Decoded point with x and y coordinates
   */
  public static decodePoint(data: BufferSourceLike, pointSize: number): EcPoint {
    const view = bytes.toUint8Array(data);
    if ((view.length === 0) || (view[0] !== 4)) {
      throw new Error("Only uncompressed point format supported");
    }
    // Per ANSI X9.62, an encoded point is a 1 byte type followed by
    // ceiling(log base 2 field-size / 8) bytes of x and the same of y.
    const n = (view.length - 1) / 2;
    if (n !== (Math.ceil(pointSize / 8))) {
      throw new Error("Point does not match field size");
    }

    const xb = view.slice(1, n + 1);
    const yb = view.slice(n + 1, n + 1 + n);

    return {
      x: xb, y: yb,
    };
  }

  /**
   * Encodes EC point to ANSI X9.62 encoded point
   * @param point EC point
   * @param pointSize Size of the point in bits
   * @returns ANSI X9.62 encoded point
   */
  public static encodePoint(point: EcPoint, pointSize: number): Uint8Array {
    // get field size in bytes (rounding up)
    const size = Math.ceil(pointSize / 8);

    // Check point data size
    if (point.x.byteLength !== size || point.y.byteLength !== size) {
      throw new Error("X,Y coordinates don't match point size criteria");
    }

    const x = bytes.toUint8Array(point.x);
    const y = bytes.toUint8Array(point.y);
    const res = new Uint8Array(size * 2 + 1);
    res[0] = 4;
    res.set(x, 1);
    res.set(y, size + 1);

    return res;
  }

  public static getSize(pointSize: number): number {
    return Math.ceil(pointSize / 8);
  }

  public static encodeSignature(signature: EcSignaturePoint, pointSize: number): Uint8Array {
    const size = this.getSize(pointSize);
    const r = bytes.toUint8Array(signature.r);
    const s = bytes.toUint8Array(signature.s);

    const res = new Uint8Array(size * 2);

    res.set(this.padStart(r, size));
    res.set(this.padStart(s, size), size);

    return res;
  }

  public static decodeSignature(data: BufferSourceLike, pointSize: number): EcSignaturePoint {
    const size = this.getSize(pointSize);
    const view = bytes.toUint8Array(data);
    if (view.length !== (size * 2)) {
      throw new Error("Incorrect size of the signature");
    }

    const r = view.slice(0, size);
    const s = view.slice(size);

    return {
      r: bytes.toArrayBuffer(this.trimStart(r)),
      s: bytes.toArrayBuffer(this.trimStart(s)),
    };
  }

  public static trimStart(data: Uint8Array): Uint8Array {
    let i = 0;
    while ((i < data.length - 1) && (data[i] === 0)) {
      i++;
    }
    if (i === 0) {
      return data;
    }

    return data.slice(i, data.length);
  }

  public static padStart(data: Uint8Array, size: number): Uint8Array {
    if (size === data.length) {
      return data;
    }

    const res = new Uint8Array(size);
    res.set(data, size - data.length);

    return res;
  }
}
