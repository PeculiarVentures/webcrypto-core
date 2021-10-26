import { SubtleCrypto } from "./subtle";

export abstract class Crypto {
  /**
   * Returns a SubtleCrypto object providing access to common cryptographic primitives,
   * like hashing, signing, encryption or decryption
   */
  public abstract readonly subtle: SubtleCrypto;

  // @internal
  public get[Symbol.toStringTag]() {
    return "Crypto";
  }

  /**
   * Generates cryptographically random values
   * @param array Is an integer-based BufferSource.
   * All elements in the array are going to be overridden with random numbers.
   */
  public abstract getRandomValues<T extends ArrayBufferView | null>(array: T): T;
}
