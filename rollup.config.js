import typescript from "rollup-plugin-typescript";
import ts from "typescript";

const pkg = require("./package.json");

const banner = [
  "/**",
  " * Copyright (c) 2019, Peculiar Ventures, All rights reserved.",
  " */",
  "",
];
const input = "src/index.ts";
const external = Object.keys(pkg.dependencies);

export default [
  // main
  {
    input,
    plugins: [
      typescript({ typescript: ts, target: "esnext", removeComments: true }),
    ],
    external,
    output: [
      {
        banner: banner.join("\n"),
        file: pkg.main,
        format: "cjs",
      }
    ]
  },
  // lib
  {
    input,
    plugins: [
      typescript({ typescript: ts, target: "esnext", removeComments: true }),
    ],
    external,
    output: [
      {
        banner: banner.join("\n"),
        file: pkg.module,
        format: "es",
      }
    ]
  },
];