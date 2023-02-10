import * as assert from "node:assert";
import * as nodeCrypto from "node:crypto";
import { Crypto, SubtleCrypto } from "../src";

context("Crypto", () => {

  class MyCrypto extends Crypto {
    public subtle = new SubtleCrypto();
    public getRandomValues<T extends ArrayBufferView | null>(array: T): T {
      if (ArrayBuffer.isView(array)) {
        const buffer = Buffer.from(array.buffer, array.byteOffset, array.byteLength);
        nodeCrypto.randomFillSync(buffer);
      }

      return array;
    }
  }

  it("Crypto matches to globalThis.Crypto", () => {
    // tslint:disable-next-line: no-shadowed-variable
    let crypto: globalThis.Crypto;
    crypto = new MyCrypto();
    assert.ok(crypto);
  });

  it("randomUUID", () => {
    const crypto = new MyCrypto();

    let counter = 1000;
    const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    while (counter--) {
      const uuid = crypto.randomUUID();
      assert.ok(new RegExp(regex).test(uuid), `UUID ${uuid} is incorrect`);
    }
  });

});
