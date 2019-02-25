export function isJWK(data: any): data is JsonWebKey {
  return typeof data === "object" && "kty" in data;
}
