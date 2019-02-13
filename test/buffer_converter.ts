import assert from "assert";
import { Convert } from "pvtsutils";
import { BufferSourceConverter } from "../src";

context("BufferSourceConverter", () => {

  const vectorHex = "1234567890abcdef";
  const vector = Convert.FromHex("1234567890abcdef");

  it("convert from Uint8Array", () => {
    const data = BufferSourceConverter.toUint8Array(new Uint8Array(vector));
    assert.equal(Convert.ToHex(data), vectorHex);
  });

  it("convert from Uint16Array", () => {
    const data = BufferSourceConverter.toUint8Array(new Uint16Array(vector));
    assert.equal(Convert.ToHex(data), vectorHex);
  });

  it("convert from ArrayBuffer", () => {
    const data = BufferSourceConverter.toUint8Array(vector);
    assert.equal(Convert.ToHex(data), vectorHex);
  });

  it("convert from Buffer", () => {
    const data = BufferSourceConverter.toUint8Array(Buffer.from(vector));
    assert.equal(Convert.ToHex(data), vectorHex);
  });

  context("isBufferSource", () => {

    it("ArayBufferView", () => {
      assert.equal(BufferSourceConverter.isBufferSource(new Uint16Array(0)), true);
    });

    it("ArayBuffer", () => {
      assert.equal(BufferSourceConverter.isBufferSource(new ArrayBuffer(0)), true);
    });

    it("Buffer", () => {
      assert.equal(BufferSourceConverter.isBufferSource(Buffer.alloc(0)), true);
    });

    it("Not BufferSource", () => {
      assert.equal(BufferSourceConverter.isBufferSource([1, 2, 3, 4, 5, 6, 7]), false);
    });

  });

});
