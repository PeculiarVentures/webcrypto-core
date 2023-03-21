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
  public randomUUID(): `${string}-${string}-${string}-${string}-${string}` {
    // Generate a random Uint8Array with 16 elements
    const b = this.getRandomValues(new Uint8Array(16));

    // Bitwise AND operation followed by OR operator to modify 6th and 8th elements of the array
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;

    // Lowercasing the result after converting each element in hexadecimal format
    const uuid = Convert.ToHex(b).toLowerCase();

    // Return the string created by extracting substrings from the given result
    return `${uuid.substring(0, 8)}-${uuid.substring(8, 12)}-${uuid.substring(12, 16)}-${uuid.substring(16, 20)}-${uuid.substring(20)}`;

  }
}
