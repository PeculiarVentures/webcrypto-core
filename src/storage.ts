import { ProviderCrypto } from "./provider";

export class ProviderStorage {
  private items: { [algorithmName: string]: ProviderCrypto; } = {};

  public get(algorithmName: string): ProviderCrypto | null {
    return this.items[algorithmName.toLowerCase()] || null;
  }

  public set(provider: ProviderCrypto): void {
    this.items[provider.name.toLowerCase()] = provider;
  }

  public removeAt(algorithmName: string): ProviderCrypto | null {
    const provider = this.get(algorithmName.toLowerCase());
    if (provider) {
      delete this.items[algorithmName];
    }
    return provider;
  }

  public has(name: string): boolean {
    return !!this.get(name);
  }

  public get length(): number {
    return Object.keys(this.items).length;
  }

  public get algorithms(): string[] {
    const algorithms: string[] = [];
    for (const key in this.items) {
      const provider = this.items[key];
      algorithms.push(provider.name);
    }
    return algorithms.sort();
  }

}
