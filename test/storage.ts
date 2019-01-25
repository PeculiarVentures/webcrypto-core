import assert from "assert";
import { ProviderStorage, RsaOaepProvider, RsaSsaProvider } from "../src";

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
