import {defineConfig} from "tsup";

export default defineConfig({
    name: "opticore-passport",
    format: ["cjs", "esm"],
    entry: ['src/index.ts'] ,
    dts: true,
    shims: true,
    skipNodeModulesBundle: true,
    clean: true
});