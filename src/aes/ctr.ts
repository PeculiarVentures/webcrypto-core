import { OperationError } from "../errors";
import { KeyUsages } from "../types";
import { AesProvider } from "./base";

export abstract class AesCtrProvider extends AesProvider {

  public readonly name = "AES-CTR";

  public usages: KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  public checkAlgorithmParams(algorithm: AesCtrParams): void {
    // counter
    this.checkRequiredProperty(algorithm, "counter");
    if (!(algorithm.counter instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.counter))) {
      throw new TypeError("counter: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
    if (algorithm.counter.byteLength !== 16) {
      throw new TypeError("iv: Must have length 16 bytes");
    }
    // length
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not a Number");
    }
    if (algorithm.length < 1) {
      throw new OperationError("length: Must be more than 0");
    }
  }

  public abstract onEncrypt(algorithm: AesCtrParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract onDecrypt(algorithm: AesCtrParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
