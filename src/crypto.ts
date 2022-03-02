import { Convert } from "pvtsutils";
import { SubtleCrypto } from "./subtle";

export abstract class Crypto implements globalThis.Crypto {
  /**
   * Returns a SubtleCrypto object providing access to common cryptographic primitives,
   * like hashing, signing, encryption or decryption
   */
  public abstract readonly subtle: SubtleCrypto;

  // @internal
  public get [Symbol.toStringTag]() {
    return "Crypto";
  }

  /**
   * Generates cryptographically random values
   * @param array Is an integer-based BufferSource.
   * All elements in the array are going to be overridden with random numbers.
   */
  public abstract getRandomValues<T extends ArrayBufferView | null>(array: T): T;

  /**
   * Generates a v4 UUID using a cryptographically secure random number generator
   * @returns UUID v4 string
   */
  public randomUUID(): string {
    const uuid = Convert.ToHex(this.getRandomValues(new Uint8Array(16))).toLowerCase();

    return `${uuid.substring(0, 8)}-${uuid.substring(8, 12)}-${uuid.substring(12, 16)}-${uuid.substring(16)}`;
  }
}
