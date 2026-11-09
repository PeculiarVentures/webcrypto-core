import { describe, expect, it, vi } from "vitest";
import { CryptoKey, EcdhEsProvider, EcdhProvider, HkdfProvider, OperationError, Pbkdf2Provider, ProviderCrypto, SubtleCrypto, X25519Provider } from "./index";

describe("deriveBits lengths", () => {
  it.each([
    { name: "ECDH P-256", Provider: EcdhProvider, namedCurve: "P-256", secretBytes: 32, backendLength: 256 },
    { name: "ECDH P-521", Provider: EcdhProvider, namedCurve: "P-521", secretBytes: 66, backendLength: 528 },
    { name: "ECDH Brainpool", Provider: EcdhProvider, namedCurve: "brainpoolP160r1", secretBytes: 20, backendLength: 160 },
    { name: "ECDH unregistered curve", Provider: EcdhProvider, namedCurve: "CUSTOM", secretBytes: 20, backendLength: null },
    { name: "ECDH-ES X25519", Provider: EcdhEsProvider, namedCurve: "X25519", secretBytes: 32, backendLength: 256 },
    { name: "ECDH-ES X448", Provider: EcdhEsProvider, namedCurve: "X448", secretBytes: 56, backendLength: 448 },
    { name: "X25519", Provider: X25519Provider, namedCurve: "X25519", secretBytes: 32, backendLength: 256 },
  ])("returns the full secret for a null length with $name", async ({ Provider, namedCurve, secretBytes, backendLength }) => {
    const provider = Reflect.construct(Provider, []) as ProviderCrypto;
    const subtle = new SubtleCrypto();
    subtle.providers.set(provider);
    const keyAlgorithm: EcKeyAlgorithm = { name: provider.name, namedCurve };
    const publicKey = CryptoKey.create(keyAlgorithm, "public", true, []);
    const privateKey = CryptoKey.create(keyAlgorithm, "private", false, ["deriveBits"]);
    const algorithm: EcdhKeyDeriveParams = { name: provider.name, public: publicKey };
    const secret = new Uint8Array(secretBytes).fill(0xa5).buffer;
    const deriveBits = vi.spyOn(provider, "onDeriveBits").mockImplementationOnce(async (_algorithm, _key, length) => {
      return length === null && backendLength === null ? secret : secret.slice(0, (length as number) >> 3);
    });

    await expect(subtle.deriveBits(algorithm, privateKey, null)).resolves.toEqual(secret);
    expect(deriveBits).toHaveBeenCalledWith(algorithm, privateKey, backendLength, { keyUsage: true });
  });

  it("uses the returned secret length rather than the curve's bit size", async () => {
    const provider = Reflect.construct(EcdhProvider, []) as EcdhProvider;
    const subtle = new SubtleCrypto();
    subtle.providers.set(provider);
    const keyAlgorithm: EcKeyAlgorithm = { name: "ECDH", namedCurve: "P-521" };
    const publicKey = CryptoKey.create(keyAlgorithm, "public", true, []);
    const privateKey = CryptoKey.create(keyAlgorithm, "private", false, ["deriveBits"]);
    const algorithm: EcdhKeyDeriveParams = { name: "ECDH", public: publicKey };
    const secret = new ArrayBuffer(66);
    vi.spyOn(provider, "onDeriveBits").mockResolvedValue(secret);

    await expect(subtle.deriveBits(algorithm, privateKey, 528)).resolves.toBe(secret);
    await expect(subtle.deriveBits(algorithm, privateKey, 536)).rejects.toThrow(OperationError);
  });

  it.each([undefined, null, 123, ""])("rejects invalid ECDH-ES curve metadata (%s) through key validation", async (namedCurve) => {
    const provider = Reflect.construct(EcdhEsProvider, []) as EcdhEsProvider;
    const subtle = new SubtleCrypto();
    subtle.providers.set(provider);
    const privateKey = CryptoKey.create({ name: provider.name, namedCurve } as EcKeyAlgorithm, "private", false, ["deriveBits"]);
    const publicKey = CryptoKey.create({ name: provider.name, namedCurve: "X25519" } as EcKeyAlgorithm, "public", true, []);
    const algorithm: EcdhKeyDeriveParams = { name: provider.name, public: publicKey };
    const validateKey = vi.spyOn(provider, "checkCryptoKey");
    const deriveBits = vi.spyOn(provider, "onDeriveBits").mockResolvedValue(new ArrayBuffer(32));

    await expect(subtle.deriveBits(algorithm, privateKey, null)).rejects.toMatchObject({ name: "InvalidAccessError" });
    await expect(subtle.deriveBits(algorithm, privateKey, 256)).rejects.toMatchObject({ name: "InvalidAccessError" });
    expect(validateKey).toHaveBeenCalledWith(privateKey, "deriveBits");
    expect(deriveBits).not.toHaveBeenCalled();
  });

  describe.each([
    { name: "HKDF", Provider: HkdfProvider, algorithm: { name: "HKDF", hash: { name: "SHA-256" }, salt: new Uint8Array(4), info: new Uint8Array(4) } },
    { name: "PBKDF2", Provider: Pbkdf2Provider, algorithm: { name: "PBKDF2", hash: { name: "SHA-256" }, salt: new Uint8Array(4), iterations: 1 } },
  ])("$name", ({ name, Provider, algorithm }) => {
    it("preserves the inherited Algorithm and CryptoKey parameter types", () => {
      const provider = Reflect.construct(Provider, []) as HkdfProvider | Pbkdf2Provider;
      const parameters: Algorithm = algorithm;
      const key: globalThis.CryptoKey = CryptoKey.create({ name }, "secret", false, ["deriveBits"]);

      provider.checkDeriveBits(parameters, key, 128);
    });

    it("rejects null before calling the backend", async () => {
      const provider = Reflect.construct(Provider, []) as ProviderCrypto;
      const subtle = new SubtleCrypto();
      subtle.providers.set(provider);
      const key = CryptoKey.create({ name }, "secret", false, ["deriveBits"]);
      const deriveBits = vi.spyOn(provider, "onDeriveBits").mockResolvedValue(new ArrayBuffer(0));

      await expect(subtle.deriveBits(algorithm, key, null)).rejects.toThrow(OperationError);
      expect(deriveBits).not.toHaveBeenCalled();
    });

    it("continues to derive an explicitly requested length", async () => {
      const provider = Reflect.construct(Provider, []) as ProviderCrypto;
      const subtle = new SubtleCrypto();
      subtle.providers.set(provider);
      const key = CryptoKey.create({ name }, "secret", false, ["deriveBits"]);
      const result = new ArrayBuffer(16);
      vi.spyOn(provider, "onDeriveBits").mockResolvedValueOnce(result);

      await expect(subtle.deriveBits(algorithm, key, 128)).resolves.toBe(result);
    });
  });
});
