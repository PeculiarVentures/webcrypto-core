var webcrypto = require("../");
var assert = require("assert");

describe("Webcrypto", () => {

    context("Prepare data", () => {

        context("Algorithm", () => {

            it("from string", () => {
                var alg = webcrypto.PrepareAlgorithm("AES-CBC");
                assert(JSON.stringify(alg), JSON.stringify({ name: "AES-CBC" }));
            });

            it("from object", () => {
                var alg = webcrypto.PrepareAlgorithm({ name: "AES-CBC" });
                assert(JSON.stringify(alg), JSON.stringify({ name: "AES-CBC" }));
            });

            it("from object with hashed algorithm as string", () => {
                var alg = webcrypto.PrepareAlgorithm({ name: "RSA-PSS", hash: "SHA-1" });
                assert(JSON.stringify(alg), JSON.stringify({ name: "RSA-PSS", hash: { name: "SHA-1" } }));
            });

            it("from object with hashed algorithm as object", () => {
                var alg = webcrypto.PrepareAlgorithm({ name: "RSA-PSS", hash: { name: "SHA-1" } });
                assert(JSON.stringify(alg), JSON.stringify({ name: "RSA-PSS", hash: { name: "SHA-1" } }));
            });

            it("from object without name", () => {
                assert.throws(() => webcrypto.PrepareAlgorithm({ wrong: "param" }), Error);
            });

        });

        context("Data", () => {

            it("from Uint8Array", () => {
                var data = webcrypto.PrepareData(new Uint8Array(10));
                assert.equal(data.length, 10);
                assert.equal(ArrayBuffer.isView(data), true);
            });

            it("from Uint16Array", () => {
                var data = webcrypto.PrepareData(new Uint16Array(10));
                assert.equal(data.byteLength, 20);
                assert.equal(ArrayBuffer.isView(data), true);
            });

            it("from Uint32Array", () => {
                var data = webcrypto.PrepareData(new Uint32Array(10));
                assert.equal(data.byteLength, 40);
                assert.equal(ArrayBuffer.isView(data), true);
            });

            it("from ArrayBuffer", () => {
                var data = webcrypto.PrepareData(new Uint8Array(10).buffer);
                assert.equal(data.byteLength, 10);
                assert.equal(ArrayBuffer.isView(data), true);
            });

            it("from wrong data", () => {
                assert.throws(() => webcrypto.PrepareData("12345"), Error);
            });

            it("empty data", () => {
                assert.throws(() => webcrypto.PrepareData(), Error);
            });
        });

    });

    context("BaseCrypto", () => {
        var BaseCrypto = webcrypto.BaseCrypto;

        context("ckeckAlgorithm", () => {
            var checkAlgorithm = BaseCrypto.checkAlgorithm;

            it("algorithm", () => {
                checkAlgorithm({ name: "AES-CBC" });
            });

            it("hashed algorithm", () => {
                checkAlgorithm({ name: "RSA-PSS", hash: "SHA-1" });
            });

            it("wrong value", () => {
                assert.throws(() => checkAlgorithm([]), Error);
            });

            it("wrong object", () => {
                assert.throws(() => checkAlgorithm({}), Error);
            });

            it("empty", () => {
                assert.throws(() => checkAlgorithm(), Error);
            });

        });

        context("checkKey", () => {
            var checkKey = BaseCrypto.checkKey;

            it("empty", () => {
                assert.throws(() => checkKey(), Error);
            });

            it("wrong alg", () => {
                assert.throws(() => checkKey({ algorithm: { name: "AES-CBC" } }, "WRONG-ALG"), Error);
            });

        });

        it("checkWrappedKey", () => {
            assert.throws(() => BaseCrypto.checkWrappedKey({ extractable: false }), Error);
        })

        context("checkFormat", () => {
            var checkFormat = BaseCrypto.checkFormat;

            ["private"].forEach(type =>
                it(`raw for ${type}`, () => {
                    assert.throws(() => checkFormat("raw", type), Error);
                })
            );

            ["private"].forEach(type =>
                it(`jwk for ${type}`, () => {
                    assert.throws(() => checkFormat("raw", type), Error);
                })
            );

            ["secret", "private"].forEach(type =>
                it(`spki for ${type}`, () => {
                    assert.throws(() => checkFormat("spki", type), Error);
                })
            );

            ["secret", "public"].forEach(type =>
                it(`pkcs8 for ${type}`, () => {
                    assert.throws(() => checkFormat("pkcs8", type), Error);
                })
            );

            it("wrong format", () => {
                assert.throws(() => checkFormat("wrong", "secret"), Error);
            });

        });

        context("Abstract methods", () => {

            ["generateKey", "digest", "sign", "verify", "encrypt", "decrypt",
                "exportKey", "importKey", "wrapKey", "unwrapKey",
                "deriveKey", "deriveBits"].forEach(method =>
                    it(`${method} not implemented`, done => {
                        BaseCrypto[method]()
                            .then(() => {
                                done(new Error("Must be error"))
                            })
                            .catch(e =>
                                done()
                            );
                    })
                );

        });

    });


});