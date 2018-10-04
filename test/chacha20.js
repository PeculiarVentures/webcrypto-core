var webcrypto = require("../");
var assert = require("assert");

var helper = require("./helper");
var encrypt = helper.encrypt;
var decrypt = helper.decrypt;

describe("Subtle", function () {

    context("ChaCha20", function () {

        it("ChaCha20 encrypt", function (done) {
            var key = {
                algorithm: {
                    name: "ECDSA",
                },
                usages: ["encrypt"],
                type: "secret"
            };
            var alg = {
                name: "CHACHA20",
                label: new Uint8Array([1, 2, 3, 4, 5, 6])
            }
            encrypt("encrypt", alg, key, done, false);
        });

        it("decrypt", (done) => {
            var key = {
                algorithm: {
                    name: "ECDSA",
                },
                usages: ["decrypt"],
                type: "secret"
            };
            var alg = {
                name: "CHACHA20",
                label: new Uint8Array([1, 2, 3, 4, 5, 6])
            }
            encrypt("decrypt", alg, key, done, false);
        });
    })
})
