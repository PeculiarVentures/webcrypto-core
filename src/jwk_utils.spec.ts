import { describe, it, expect } from "vitest";
import * as crypto from "node:crypto";
import * as encoding from "@peculiar/utils/encoding";
import { JwkUtils } from "./index";

// crypto.webcrypto
const ctx = crypto.webcrypto ? describe : describe.skip;

ctx("JWK utils", () => {
  it("format with odd removing", () => {
    const jwk: JsonWebKey = {
      n: "n value",
      ext: true,
      e: "e value",
    };

    const formattedJwk = JwkUtils.format(jwk, true);
    expect(JSON.stringify(formattedJwk)).toBe(
      JSON.stringify({
        e: "e value",
        n: "n value",
      }),
    );
  });

  it("format without removing", () => {
    const jwk: JsonWebKey = {
      n: "n value",
      ext: true,
      e: "e value",
    };

    const formattedJwk = JwkUtils.format(jwk, false);
    expect(JSON.stringify(formattedJwk)).toBe(
      JSON.stringify({
        e: "e value",
        ext: true,
        n: "n value",
      }),
    );
  });

  it("thumbprint", async () => {
    const digest = await JwkUtils.thumbprint(
      "SHA-256",
      {
        e: "e value",
        n: "n value",
      },
      crypto.webcrypto as any,
    );

    expect(encoding.base64.encode(digest)).toBe("MkHJT3yHfy0O9t4OHK/331Pb3HNa4LRG62yPa4NNnSc=");
  });
});
