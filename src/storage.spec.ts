import { describe, it, expect } from "vitest";
import { ProviderStorage, CryptoKey } from "./index";
import * as rsa from "./rsa";

class RsaSsaProvider extends rsa.RsaSsaProvider {
  public onSign(_algorithm: rsa.RsaSsaParams, _key: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }

  public onVerify(_algorithm: rsa.RsaSsaParams, _key: CryptoKey, _signature: ArrayBuffer, _data: ArrayBuffer): Promise<boolean> {
    throw new Error("Method not implemented.");
  }

  public onGenerateKey(_algorithm: RsaHashedKeyGenParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    throw new Error("Method not implemented.");
  }

  public onExportKey(_format: KeyFormat, _key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    throw new Error("Method not implemented.");
  }

  public onImportKey(_format: KeyFormat, _keyData: ArrayBuffer | JsonWebKey, _algorithm: RsaHashedImportParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }
}

class RsaOaepProvider extends rsa.RsaOaepProvider {
  public onEncrypt(_algorithm: RsaOaepParams, _key: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }

  public onDecrypt(_algorithm: RsaOaepParams, _key: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }

  public onGenerateKey(_algorithm: RsaHashedKeyGenParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    throw new Error("Method not implemented.");
  }

  public onExportKey(_format: KeyFormat, _key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    throw new Error("Method not implemented.");
  }

  public onImportKey(_format: KeyFormat, _keyData: ArrayBuffer | JsonWebKey, _algorithm: RsaHashedImportParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }
}

describe("ProviderStorage", () => {
  it("set", () => {
    const storage = new ProviderStorage();

    expect(storage.length).toBe(0);

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());
    storage.set(new RsaOaepProvider());

    expect(storage.length).toBe(2);
  });

  it("get", () => {
    const storage = new ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    const provider = storage.get("rsa-oaep");
    expect(provider!.name).toBe("RSA-OAEP");
  });

  it("has", () => {
    const storage = new ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    const ok = storage.has("rsa-oaep");
    expect(ok).toBe(true);
  });

  it("algorithms", () => {
    const storage = new ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    expect(storage.algorithms).toEqual(["RSA-OAEP", "RSASSA-PKCS1-v1_5"]);
  });

  it("removeAt", () => {
    const storage = new ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    storage.removeAt("rsa-wrong");
    expect(storage.length).toEqual(2);

    const removedProvider = storage.removeAt("rsa-oaep");
    expect(removedProvider!.name).toEqual("RSA-OAEP");
    expect(storage.length).toEqual(1);
  });
});
