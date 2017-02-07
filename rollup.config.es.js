import typescript from "rollup-plugin-typescript";

let pkg = require("./package.json");

let banner = []

export default {
    entry: "src/index.ts",
    plugins: [
        typescript({ typescript: require("typescript"), target: "es5", removeComments: true }),
    ],
    external: ["tslib"],
    banner: banner.join("\n"),
    targets: [
        {
            dest: pkg.module,
            format: "es",
        }
    ]
};