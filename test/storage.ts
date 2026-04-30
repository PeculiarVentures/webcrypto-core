import assert from "node:assert";
import { ProviderStorage, CryptoKey } from "../src";
import * as rsa from "../src/rsa";

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

    assert.equal(storage.length, 0);

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());
    storage.set(new RsaOaepProvider());

    assert.equal(storage.length, 2);
  });

  it("get", () => {
    const storage = new ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    const provider = storage.get("rsa-oaep");
    assert.equal(provider!.name, "RSA-OAEP");
  });

  it("has", () => {
    const storage = new ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    const ok = storage.has("rsa-oaep");
    assert.equal(ok, true);
  });

  it("algorithms", () => {
    const storage = new ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    assert.deepEqual(storage.algorithms, ["RSA-OAEP", "RSASSA-PKCS1-v1_5"]);
  });

  it("removeAt", () => {
    const storage = new ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    storage.removeAt("rsa-wrong");
    assert.deepEqual(storage.length, 2);

    const removedProvider = storage.removeAt("rsa-oaep");
    assert.deepEqual(removedProvider!.name, "RSA-OAEP");
    assert.deepEqual(storage.length, 1);
  });
});
