import path from "node:path";
import url from "node:url";
import typescript from "@rollup/plugin-typescript";
import { dts } from "rollup-plugin-dts";
import pkg from "./package.json" with { type: "json" };

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const startYear = 2019;
const currentYear = new Date().getFullYear();

const year
  = startYear === currentYear
    ? `${startYear}`
    : `${startYear}-${currentYear}`;

const banner = [
  "/**",
  ` * Copyright (c) ${year}, Peculiar Ventures`,
  " * SPDX-License-Identifier: MIT",
  " */",
  "",
].join("\n");
const input = "src/index.ts";
const externalDeps = new Set([
  "node:crypto",
  "node:process",
  "node:buffer",
  ...Object.keys(pkg.dependencies || {}),
]);

const external = (id) => {
  return [...externalDeps].some((dep) => {
    return id === dep || id.startsWith(`${dep}/`);
  });
};

export default [
  {
    input,
    plugins: [
      typescript({
        tsconfig: "./tsconfig.json",
        compilerOptions: { module: "ES2015" },
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
  {
    input,
    external,
    plugins: [
      dts({ tsconfig: path.resolve(__dirname, "./tsconfig.json") }),
    ],
    output: [
      {
        banner,
        file: pkg.types,
      },
    ],
  },
];
