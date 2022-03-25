import * as assert from "assert";
import * as crypto from "crypto";
import { Convert } from "pvtsutils";
import { JwkUtils } from "../src";

// crypto.webcrypto
const ctx = crypto.webcrypto ? context : context.skip;

ctx("JWK utils", () => {

  it("format with odd removing", () => {
    const jwk: JsonWebKey = {
      n: "n value",
      ext: true,
      e: "e value",
    };

    const formattedJwk = JwkUtils.format(jwk, true);
    assert.strictEqual(JSON.stringify(formattedJwk), JSON.stringify({
      e: "e value",
      n: "n value",
    }));
  });

  it("format without removing", () => {
    const jwk: JsonWebKey = {
      n: "n value",
      ext: true,
      e: "e value",
    };

    const formattedJwk = JwkUtils.format(jwk, false);
    assert.strictEqual(JSON.stringify(formattedJwk), JSON.stringify({
      e: "e value",
      ext: true,
      n: "n value",
    }));
  });

  it("thumbprint", async () => {
    const digest = await JwkUtils.thumbprint("SHA-256", {
      e: "e value",
      n: "n value",
    }, crypto.webcrypto as any);

    assert.strictEqual(Convert.ToBase64(digest), "MkHJT3yHfy0O9t4OHK/331Pb3HNa4LRG62yPa4NNnSc=");
  });

});
