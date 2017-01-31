var helper = require("./helper");
var generate = helper.generate;
var sign = helper.sign;
var verify = helper.verify;
var deriveKey = helper.deriveKey;
var exportKey = helper.exportKey;
var importKey = helper.importKey;

var keyUsages = {
    ecdsa: ["sign", "verify"],
    ecdh: ["deriveKey", "deriveBits"],
}

describe("Subtle", function () {

    context("EC", function () {

        context("generate", function () {

            ["ecdsa", "ecdh"]
                .forEach(function (alg) {

                    ["P-256", "P-384", "P-521", "Wrong curve"]
                        .forEach(function (namedCurve, index) {

                            it(alg + " " + namedCurve, function (done) {
                                var _alg = {
                                    name: alg,
                                    namedCurve: namedCurve
                                };
                                generate(_alg, keyUsages[alg], done, index === 3)
                            });

                        });

                });

            it("wrong usage", function (done) {
                var _alg = {
                    name: "ecdsa",
                    namedCurve: "p-256"
                };
                generate(_alg, ["encrypt"], done, true);
            })

        }); // generate

        context("ECDSA sign/verify", function () {

            ["sha-1", "sha-256", "sha-384", "sha-512", "wrong hash alg"]
                .forEach(function (hashAlg, index) {

                    it("sign " + hashAlg, function (done) {
                        var _key = {
                            type: "private",
                            algorithm: {
                                name: "ecdsa"
                            },
                            usages: ["sign"]
                        };
                        var _alg = {
                            name: "ecdsa",
                            hash: {
                                name: hashAlg
                            }
                        }
                        sign(_alg, _key, done, index === 4);
                    });

                    it("verify " + hashAlg, function (done) {
                        var _key = {
                            type: "public",
                            algorithm: {
                                name: "ecdsa"
                            },
                            usages: ["verify"]
                        };
                        var _alg = {
                            name: "ecdsa",
                            hash: {
                                name: hashAlg
                            }
                        }
                        verify(_alg, _key, done, index === 4);
                    });

                });

            it("sign wrong key type", function (done) {
                var _key = {
                    type: "public",
                    algorithm: {
                        name: "ecdsa"
                    },
                    usages: ["sign"]
                };
                var _alg = {
                    name: "ecdsa",
                    hash: {
                        name: "sha-1"
                    }
                }
                sign(_alg, _key, done, true);
            });
            it("sign wrong key usage", function (done) {
                var _key = {
                    type: "private",
                    algorithm: {
                        name: "ecdsa"
                    },
                    usages: ["verify"]
                };
                var _alg = {
                    name: "ecdsa",
                    hash: {
                        name: "sha-1"
                    }
                }
                sign(_alg, _key, done, true);
            });
            it("verify wrong key type", function (done) {
                var _key = {
                    type: "private",
                    algorithm: {
                        name: "ecdsa"
                    },
                    usages: ["verify"]
                };
                var _alg = {
                    name: "ecdsa",
                    hash: {
                        name: "sha-1"
                    }
                }
                verify(_alg, _key, done, true);
            });
            it("verify wrong key usage", function (done) {
                var _key = {
                    type: "public",
                    algorithm: {
                        name: "ecdsa"
                    },
                    usages: ["sign"]
                };
                var _alg = {
                    name: "ecdsa",
                    hash: {
                        name: "sha-1"
                    }
                }
                verify(_alg, _key, done, true);
            });
        });

        context("ECDH deriveKey", function () {

            ["aes-cbc", "aes-ctr", "aes-gcm"]
                .forEach(function (aesAlg) {

                    it(aesAlg, function (done) {
                        var _alg = {
                            name: "ecdh",
                            public: {
                                type: "public",
                                algorithm: {
                                    name: "ecdh"
                                }
                            }
                        }
                        var _key = {
                            algorithm: {
                                name: "ecdh"
                            },
                            type: "private",
                            usages: ["deriveKey"]
                        }
                        var derAlg = {
                            name: aesAlg,
                            length: 128
                        }
                        deriveKey(_alg, _key, derAlg, ["encrypt"], done, false);
                    });

                });

            it("wrong derived key alg", function (done) {
                var _alg = {
                    name: "ecdh",
                    public: {
                        type: "public",
                        algorithm: {
                            name: "wrong"
                        }
                    }
                }
                var _key = {
                    algorithm: {
                        name: "ecdh"
                    },
                    type: "private",
                    usages: ["deriveKey"]
                }
                var derAlg = {
                    name: "aes-ctr",
                    length: 128
                }
                deriveKey(_alg, _key, derAlg, ["encrypt"], done, true);
            });

            it("wrong derived key type", function (done) {
                var _alg = {
                    name: "ecdh",
                    public: {
                        type: "private",
                        algorithm: {
                            name: "ecdh"
                        }
                    }
                }
                var _key = {
                    algorithm: {
                        name: "ecdh"
                    },
                    type: "private",
                    usages: ["deriveKey"]
                }
                var derAlg = {
                    name: "aes-ctr",
                    length: 128
                }
                deriveKey(_alg, _key, derAlg, ["encrypt"], done, true);
            });

            it("wrong key alg", function (done) {
                var _alg = {
                    name: "ecdh",
                    public: {
                        type: "public",
                        algorithm: {
                            name: "ecdh"
                        }
                    }
                }
                var _key = {
                    algorithm: {
                        name: "ecdsa"
                    },
                    type: "private",
                    usages: ["deriveKey"]
                }
                var derAlg = {
                    name: "aes-ctr",
                    length: 128
                }
                deriveKey(_alg, _key, derAlg, ["encrypt"], done, true);
            });

            it("wrong AES alg", function (done) {
                var _alg = {
                    name: "ecdh",
                    public: {
                        type: "public",
                        algorithm: {
                            name: "ecdh"
                        }
                    }
                }
                var _key = {
                    algorithm: {
                        name: "ecdh"
                    },
                    type: "private",
                    usages: ["deriveKey"]
                }
                var derAlg = {
                    name: "aes",
                    length: 128
                }
                deriveKey(_alg, _key, derAlg, ["encrypt"], done, true);
            });

        }); // deriveKey

        context("import/export ECDSA", function () {

            it("import raw", function (done) {
                var alg = {
                    name: "ecdsa",
                    namedCurve: "p-256"
                }
                importKey("raw", {}, alg, ["sign"], done, false);
            });

            it("import jwk", function (done) {
                var alg = {
                    name: "ecdsa",
                    namedCurve: "p-256"
                }
                importKey("jwk", {}, alg, ["sign"], done, false);
            });

            it("import spki", function (done) {
                var alg = {
                    name: "ecdsa",
                    namedCurve: "p-256"
                }
                importKey("spki", new Uint8Array(5), alg, ["verify"], done, false);
            });

            it("import wrong alg namedCurver", function (done) {
                var alg = {
                    name: "ecdsa",
                    namedCurve: "wrong"
                }
                importKey("jwk", {}, alg, ["sign"], done, true);
            });

            it("import", function (done) {
                var alg = {
                    name: "ecdsa",
                    namedCurve: "p-256"
                }
                importKey("jwk", {}, alg, ["sign"], done, false);
            });

            // export

            it("export raw", function (done) {
                var key = {
                    algorithm: {
                        name: "ecdsa"
                    },
                    type: "public",
                    extractable: true
                };
                exportKey("raw", key, done, false);
            });

            it("export", function (done) {
                var key = {
                    algorithm: {
                        name: "ecdsa"
                    },
                    type: "public",
                    extractable: true
                };
                exportKey("jwk", key, done, false);
            });

            it("export not extractable", function (done) {
                var key = {
                    algorithm: {
                        name: "ecdsa"
                    },
                    type: "public",
                    extractable: false
                };
                exportKey("jwk", key, done, true);
            });

        }); // import/export

    });

});