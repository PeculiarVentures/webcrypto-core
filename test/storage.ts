import assert from "assert";
import { ProviderStorage, CryptoKeyPair, CryptoKey } from "../src";
import * as rsa from "../src/rsa";

// tslint:disable:max-classes-per-file

class RsaSsaProvider extends rsa.RsaSsaProvider {
  public onSign(algorithm: rsa.RsaSsaParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public onVerify(algorithm: rsa.RsaSsaParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    throw new Error("Method not implemented.");
  }
  public onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    throw new Error("Method not implemented.");
  }
  public onExportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    throw new Error("Method not implemented.");
  }
  public onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }
}

class RsaOaepProvider extends rsa.RsaOaepProvider {
  public onEncrypt(algorithm: RsaOaepParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public onDecrypt(algorithm: RsaOaepParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    throw new Error("Method not implemented.");
  }
  public onExportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    throw new Error("Method not implemented.");
  }
  public onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }
}

context("ProviderStorage", () => {

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
