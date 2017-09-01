import typescript from "rollup-plugin-typescript";

const pkg = require("./package.json");

const banner = [pkg.banner, ""];

export default {
    input: "src/index.ts",
    plugins: [
        typescript({ typescript: require("typescript"), target: "es5", removeComments: true }),
    ],
    external: ["tslib"],
    banner: banner.join("\n"),
    output: [
        {
            file: pkg.main,
            format: "cjs",
        }
    ]
};