// @ts-check
import { ts, dts } from "rollup-plugin-dts";
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
      ts({
        compilerOptions: {
          removeComments: true,
        },
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
      }
    ]
  },
  // lib
  {
    input,
    plugins: [
      dts(),
    ],
    external,
    output: [
      {
        file: pkg.types,
        format: "es",
      }
    ]
  },
];