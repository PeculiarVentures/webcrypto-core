import { describe, expect, it, vi } from "vitest";
import { AesGcmProvider, CryptoKey, HkdfProvider, HmacProvider, OperationError, Pbkdf2Provider, ProviderCrypto, SubtleCrypto } from "./index";

class CustomProvider extends ProviderCrypto {
  public name = "CUSTOM";
  public usages: KeyUsage[] = ["deriveBits", "deriveKey", "sign"];
}

function setup(target: ProviderCrypto, secretBytes = 32) {
  const subtle = new SubtleCrypto();
  const source = new CustomProvider();
  source.name = "SOURCE";
  const secret = new Uint8Array(secretBytes).fill(0xa5).buffer;
  const deriveBits = vi.spyOn(source, "onDeriveBits").mockImplementation(async (_algorithm, _key, length) => secret.slice(0, length === null ? secret.byteLength : length / 8));
  const importKey = vi.spyOn(target, "onImportKey").mockImplementation(async (_format, data, algorithm, extractable, usages) => {
    return CryptoKey.create({ ...algorithm, length: (data as ArrayBuffer).byteLength * 8 } as AesKeyAlgorithm, "secret", extractable, usages);
  });
  subtle.providers.set(source);
  subtle.providers.set(target);
  const baseKey = CryptoKey.create({ name: source.name }, "secret", false, ["deriveKey"]);
  return { subtle, source, secret, baseKey, deriveBits, importKey };
}

describe("deriveKey target lengths", () => {
  it.each([HkdfProvider, Pbkdf2Provider])("imports the full source secret into %s", async (Provider) => {
    const target = Reflect.construct(Provider, []) as ProviderCrypto;
    const { subtle, source, secret, baseKey, deriveBits, importKey } = setup(target);

    const key = await subtle.deriveKey(source.name, baseKey, target.name, false, ["deriveBits"]);

    expect(key.algorithm).toMatchObject({ name: target.name, length: 256 });
    expect(deriveBits).toHaveBeenCalledWith({ name: source.name }, baseKey, null, { keyUsage: false });
    expect(importKey).toHaveBeenCalledWith("raw", secret, { name: target.name }, false, ["deriveBits"]);
  });

  it.each([128, 192, 256])("requests %i bits for AES", async (length) => {
    const target = Reflect.construct(AesGcmProvider, []) as AesGcmProvider;
    const { subtle, source, baseKey } = setup(target);
    const algorithm: AesKeyGenParams = { name: target.name, length };

    const key = await subtle.deriveKey(source.name, baseKey, algorithm, true, ["encrypt"]);

    expect(key.algorithm).toMatchObject({ name: target.name, length });
  });

  it("rejects invalid AES lengths before deriving bits", async () => {
    const target = Reflect.construct(AesGcmProvider, []) as AesGcmProvider;
    const { subtle, source, baseKey, deriveBits } = setup(target);
    const algorithm: AesKeyGenParams = { name: target.name, length: 64 };

    await expect(subtle.deriveKey(source.name, baseKey, algorithm, true, ["encrypt"])).rejects.toThrow(OperationError);
    expect(deriveBits).not.toHaveBeenCalled();
  });

  it.each([
    ["SHA-1", 512],
    ["SHA-256", 512],
    ["SHA-384", 1024],
    ["SHA-512", 1024],
  ] as const)("uses the %s block size for HMAC when length is omitted", async (hash, length) => {
    const target = Reflect.construct(HmacProvider, []) as HmacProvider;
    const { subtle, source, baseKey, deriveBits } = setup(target, 128);
    const algorithm: HmacKeyGenParams = { name: target.name, hash };

    const key = await subtle.deriveKey(source.name, baseKey, algorithm, true, ["sign"]);

    expect(key.algorithm).toMatchObject({ name: target.name, hash: { name: hash }, length });
    expect(deriveBits).toHaveBeenCalledWith({ name: source.name }, baseKey, length, { keyUsage: false });
  });

  it("honors an explicit HMAC length", async () => {
    const target = Reflect.construct(HmacProvider, []) as HmacProvider;
    const { subtle, source, baseKey } = setup(target);
    const algorithm: HmacKeyGenParams = { name: target.name, hash: "SHA-512", length: 128 };

    const key = await subtle.deriveKey(source.name, baseKey, algorithm, true, ["sign"]);

    expect(key.algorithm).toMatchObject({ length: 128 });
  });

  it("rejects a short source secret before importing HMAC", async () => {
    const target = Reflect.construct(HmacProvider, []) as HmacProvider;
    const { subtle, source, baseKey, importKey } = setup(target);
    const algorithm: HmacKeyGenParams = { name: target.name, hash: "SHA-256", length: 512 };

    await expect(subtle.deriveKey(source.name, baseKey, algorithm, true, ["sign"])).rejects.toThrow(OperationError);
    expect(importKey).not.toHaveBeenCalled();
  });

  it("rejects a zero HMAC length instead of using a default", async () => {
    const target = Reflect.construct(HmacProvider, []) as HmacProvider;
    const { subtle, source, baseKey, deriveBits } = setup(target);
    const algorithm: HmacKeyGenParams = { name: target.name, hash: "SHA-256", length: 0 };

    await expect(subtle.deriveKey(source.name, baseKey, algorithm, true, ["sign"])).rejects.toThrow(TypeError);
    expect(deriveBits).not.toHaveBeenCalled();
  });

  it.each([undefined, 128, 0])("preserves the legacy fallback for a custom provider with length %s", async (length) => {
    const target = new CustomProvider();
    const { subtle, source, baseKey, deriveBits } = setup(target, 64);
    const algorithm = { name: target.name, ...(length === undefined ? {} : { length }) };

    await subtle.deriveKey(source.name, baseKey, algorithm, true, ["sign"]);

    expect(deriveBits).toHaveBeenCalledWith({ name: source.name }, baseKey, length || 512, { keyUsage: false });
  });

  it.each([160, null])("allows custom target providers to resolve a key length of %s", async (length) => {
    class ExtensibleProvider extends CustomProvider {
      public override getKeyLength(_algorithm: Algorithm): number | null {
        return length;
      }
    }
    const target = new ExtensibleProvider();
    const { subtle, source, baseKey, deriveBits } = setup(target);

    const key = await subtle.deriveKey(source.name, baseKey, target.name, true, ["sign"]);

    expect(key.algorithm).toMatchObject({ length: length ?? 256 });
    expect(deriveBits).toHaveBeenCalledWith({ name: source.name }, baseKey, length, { keyUsage: false });
  });
});
