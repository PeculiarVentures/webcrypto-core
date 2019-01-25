export type KeyUsages = KeyUsage[];

export type ProviderKeyUsage = KeyUsages;

export interface ProviderKeyPairUsage {
  privateKey: KeyUsages;
  publicKey: KeyUsages;
}

export type ProviderKeyUsages = ProviderKeyUsage | ProviderKeyPairUsage;

export interface HashedAlgorithm extends Algorithm {
  hash: AlgorithmIdentifier;
}
