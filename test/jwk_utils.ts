import * as assert from "assert";
import { JwkUtils } from "../src";
import { Crypto } from "@peculiar/webcrypto";
import { Convert } from "pvtsutils";

context("JWK utils", () => {

  const crypto = new Crypto();

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
    }, crypto);

    assert.strictEqual(Convert.ToBase64(digest), "MkHJT3yHfy0O9t4OHK/331Pb3HNa4LRG62yPa4NNnSc=");
  });

});
