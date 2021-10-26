import * as assert from "assert";
import { Crypto, SubtleCrypto } from "../src";

context("Crypto", () => {

  it("Crypto matches to globalThis.Crypto", () => {
    class MyCrypto extends Crypto {
      public subtle = new SubtleCrypto();
      public getRandomValues<T extends ArrayBufferView | null>(array: T): T {
        throw new Error("Method not implemented.");
      }

    }

    let crypto: globalThis.Crypto;
    crypto = new MyCrypto();
    assert.ok(crypto);
  });

});
