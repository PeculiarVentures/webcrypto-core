export class BufferSourceConverter {

  public static toArrayBuffer(data: BufferSource) {
    const buf = this.toUint8Array(data);
    if (buf.byteOffset || buf.length) {
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length);
    }
    return buf.buffer;
  }

  public static toUint8Array(data: BufferSource) {
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(data)) {
      return new Uint8Array(data);
    }
    if (ArrayBuffer.isView(data)) {
      return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    }
    if (data instanceof ArrayBuffer) {
      return new Uint8Array(data);
    }
    throw new TypeError("The provided value is not of type '(ArrayBuffer or ArrayBufferView)'");
  }

  public static isBufferSource(data: any): data is BufferSource {
    return ArrayBuffer.isView(data) || data instanceof ArrayBuffer;
  }

}
