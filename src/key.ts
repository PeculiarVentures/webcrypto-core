import { KeyUsages, NativeCryptoKey } from "./types";

// tslint:disable-next-line:no-empty-interface
export interface KeyAlgorithm extends Algorithm {
}

const KEY_TYPES = ["secret", "private", "public"];

export class CryptoKey implements NativeCryptoKey {

  public static create<T extends CryptoKey>(this: new() => T, algorithm: KeyAlgorithm, type: KeyType, extractable: boolean, usages: KeyUsages): T {
    const key = new this();
    key.algorithm = algorithm;
    key.type = type;
    key.extractable = extractable;
    key.usages = usages;

    return key;
  }

  public static isKeyType(data: any): data is KeyType {
    return KEY_TYPES.indexOf(data) !== -1;
  }

  public algorithm!: KeyAlgorithm;
  public type!: KeyType;
  public usages!: KeyUsages;
  public extractable!: boolean;

  public get[Symbol.toStringTag]() {
    return "CryptoKey";
  }
}
