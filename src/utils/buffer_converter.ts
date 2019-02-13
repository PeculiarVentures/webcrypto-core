export class BufferSourceConverter {

  public static toArrayBuffer(data: BufferSource) {
    if (data instanceof ArrayBuffer) {
      return data;
    }
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(data)) {
      return new Uint8Array(data);
    }
    if (ArrayBuffer.isView(data)) {
      return data.buffer;
    }
    throw new TypeError("The provided value is not of type '(ArrayBuffer or ArrayBufferView)'");
  }

  public static toUint8Array(data: BufferSource) {
    return new Uint8Array(this.toArrayBuffer(data));
  }

  public static isBufferSource(data: any): data is BufferSource {
    return ArrayBuffer.isView(data) || data instanceof ArrayBuffer;
  }

}
