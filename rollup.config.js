import typescript from "rollup-plugin-typescript2";
// @ts-ignore
import pkg from "./package.json";

const banner = [
  "/**",
  " * Copyright (c) 2019, Peculiar Ventures, All rights reserved.",
  " */",
  "",
].join("\n");
const input = "src/index.ts";
const external = Object.keys(pkg.dependencies);


export default [
  // main
  {
    input,
    plugins: [
      typescript({
        check: true,
        clean: true,
      }),
    ],
    external,
    output: [
      {
        banner,
        file: pkg.main,
        format: "cjs",
      },
      {
        banner,
        file: pkg.module,
        format: "es",
      },
    ],
  },
];
