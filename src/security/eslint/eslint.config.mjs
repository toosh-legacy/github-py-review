// Flat config for the JS/TS half of the code detector.
//
// Only eslint-plugin-security rules are enabled: this is a security scanner,
// not a style checker, and every extra rule is a finding the user has to
// dismiss.
//
// ESLint 9 will not lint files outside its config's base path, so `code_scan.py`
// re-exports this config from inside the temporary scan directory. The plugins
// are therefore resolved explicitly against *this* file's node_modules via
// createRequire — plain bare imports would be looked up next to the temporary
// copy, where nothing is installed.
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const security = require("eslint-plugin-security");
const tsParser = require("@typescript-eslint/parser");

export default [
  {
    files: ["**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts}"],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: { security },
    rules: {
      // Injection and code execution — the categories this scanner is about.
      "security/detect-eval-with-expression": "error",
      "security/detect-child-process": "error",
      "security/detect-non-literal-require": "error",
      "security/detect-unsafe-regex": "error",
      "security/detect-buffer-noassert": "error",
      "security/detect-disable-mustache-escape": "error",
      "security/detect-new-buffer": "error",
      "security/detect-no-csrf-before-method-override": "error",
      "security/detect-possible-timing-attacks": "warn",
      "security/detect-pseudoRandomBytes": "error",
      // Path and property access — real, but more context-dependent, so they
      // enter as warnings and the triage stage decides whether they matter.
      "security/detect-non-literal-fs-filename": "warn",
      "security/detect-non-literal-regexp": "warn",
      "security/detect-object-injection": "warn",
    },
  },
];
