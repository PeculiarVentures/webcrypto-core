var helper = require("./helper");
var generate = helper.generate;
var encrypt = helper.encrypt;
var exportKey = helper.exportKey;
var importKey = helper.importKey;

describe("Subtle", function () {

    context("AES", function () {

        var algs = ["AES-CBC", "AES-CTR", "AES-GCM"];
        algs.forEach(function (alg) {

            it(alg + " generate 128", function (done) {
                generate({ name: alg, length: 128 }, ["encrypt", "decrypt", "wrapKey", "unwrapKey"], done, false);
            });
            it(alg + " generate 196", function (done) {
                generate({ name: alg, length: 196 }, ["encrypt", "decrypt", "wrapKey", "unwrapKey"], done, false);
            });
            it(alg + " generate 256", function (done) {
                generate({ name: alg, length: 256 }, ["encrypt", "decrypt", "wrapKey", "unwrapKey"], done, false);
            });
            it(alg + " generate 111, wrong length", function (done) {
                generate({ name: alg, length: 111 }, ["encrypt", "decrypt", "wrapKey", "unwrapKey"], done, true);
            });
            it(alg + " generate with wrong key usage", function (done) {
                generate({ name: alg, length: 256 }, ["sign"], done, true);
            });
            it(alg + " generate with key usage = null", function (done) {
                generate({ name: alg, length: 256 }, null, done, true);
            });
            it(alg + " generate with empty key usage", function (done) {
                generate({ name: alg, length: 256 }, [], done, true);
            });
            it(alg + " export raw", function (done) {
                var key = {algorithm: {name: alg}, type:"secret", extractable: true};
                exportKey("raw", key, done, false);
            });
            it(alg + " export jwk", function (done) {
                var key = {algorithm: {name: alg}, type:"secret", extractable: true};
                exportKey("jwk", key, done, false);
            });
            it(alg + " export pkcs8, wrong format", function (done) {
                var key = {algorithm: {name: alg}, type:"secret", extractable: true};
                exportKey("pkcs8", key, done, true);
            });
            it(alg + " import jwk", function (done) {
                var _alg = {name: alg};
                importKey("jwk", new Uint8Array(3), _alg, ["encrypt"], done, false);
            });
            it(alg + " import raw", function (done) {
                var _alg = {name: alg};
                importKey("raw", new Uint8Array(3), _alg, ["encrypt"], done, false);
            });
            it(alg + " import pkcs8, wrong format", function (done) {
                var _alg = {name: alg};
                importKey("pkcs8", new Uint8Array(3), _alg, ["encrypt"], done, true);
            });
            it(alg + " import raw, wrong key usage", function (done) {
                var _alg = {name: alg};
                importKey("raw", new Uint8Array(3), _alg, ["sign"], done, true);
            });
        });

        it("AES-CBC encrypt", function (done) {
            var alg = { name: "AES-CBC", iv: new Uint8Array(16) };
            var key = {
                algorithm: { name: "AES-CBC" },
                type: "secret",
                usages: ["encrypt"]
            };
            encrypt("encrypt", alg, key, done, false);
        });
        it("AES-CBC decrypt", function (done) {
            var alg = { name: "AES-CBC", iv: new Uint8Array(16) };
            var key = {
                algorithm: { name: "AES-CBC" },
                type: "secret",
                usages: ["decrypt"]
            };
            encrypt("decrypt", alg, key, done, false);
        });
        it("AES-CBC decrypt, wrong key", function (done) {
            var alg = { name: "AES-CBC", iv: new Uint8Array(16) };
            var key = {
                algorithm: { name: "AES-GCM" },
                type: "secret",
                usages: ["decrypt"]
            };
            encrypt("decrypt", alg, key, done, true);
        });
        it("AES-CBC decrypt, wrong alg param, iv size 15", function (done) {
            var alg = { name: "AES-CBC", iv: new Uint8Array(15) };
            var key = {
                algorithm: { name: "AES-CBC" },
                type: "secret",
                usages: ["decrypt"]
            };
            encrypt("decrypt", alg, key, done, true);
        });
        it("AES-CBC decrypt, wrong key usage", function (done) {
            var alg = { name: "AES-CBC", iv: new Uint8Array(16) };
            var key = {
                algorithm: { name: "AES-CBC" },
                type: "secret",
                usages: ["unwrapKey"]
            };
            encrypt("decrypt", alg, key, done, true);
        });
        it("AES-CTR encrypt", function (done) {
            var alg = { name: "AES-CTR", counter: new Uint8Array(16), length: 1 };
            var key = {
                algorithm: { name: "AES-CTR" },
                type: "secret",
                usages: ["encrypt"]
            };
            encrypt("encrypt", alg, key, done, false);
        });
        it("AES-CTR decrypt", function (done) {
            var alg = { name: "AES-CTR", counter: new Uint8Array(16), length: 1 };
            var key = {
                algorithm: { name: "AES-CTR" },
                type: "secret",
                usages: ["decrypt"]
            };
            encrypt("decrypt", alg, key, done, false);
        });
        it("AES-CTR decrypt, wrong alg param, counter size 15", function (done) {
            var alg = { name: "AES-CTR", counter: new Uint8Array(15), length: 1 };
            var key = {
                algorithm: { name: "AES-CTR" },
                type: "secret",
                usages: ["decrypt"]
            };
            encrypt("decrypt", alg, key, done, true);
        });
        it("AES-CTR decrypt, wrong alg param, length", function (done) {
            var alg = { name: "AES-CTR", counter: new Uint8Array(16), length: 256 };
            var key = {
                algorithm: { name: "AES-CTR" },
                type: "secret",
                usages: ["decrypt"]
            };
            encrypt("decrypt", alg, key, done, true);
        });

    })

})