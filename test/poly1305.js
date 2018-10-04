var webcrypto = require("../");
var assert = require("assert");

var helper = require("./helper");
var generate = helper.generate;
var sign = helper.sign;
var verify = helper.verify;
var exportKey = helper.exportKey;
var importKey = helper.importKey;

describe("Subtle", function () {

    context("Poly1305", function () {

        context("exportKey", function (alg) {
        
        })

        context("importKey", function (alg) {
        
        })

        context("sign/verify", function (alg) {
            it("sign", function (done) {
                var _key = {
                    type: "secret",
                    algorithm: {
                        name: "EDDSA",
                    },
                    usages: ["sign"]
                };
                var _alg = {
                    name: "Poly1305",
                }
                sign(_alg, _key, done, false);
            });

            it("verify", function (done) {
                var _key = {
                    type: "secret",
                    algorithm: {
                        name: "EDDSA",
                    },
                    usages: ["verify"]
                };
                var _alg = {
                    name: "Poly1305"
                }
                verify(_alg, _key, done, false);
            });
        })
    })
})
