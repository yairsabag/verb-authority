import { spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(packageRoot, "dist");
const typescriptRoot = dirname(require.resolve("typescript/package.json"));
const compiler = join(typescriptRoot, "bin", "tsc");

if (dirname(dist) !== packageRoot || dist !== join(packageRoot, "dist")) {
  throw new Error("refusing to clean an unexpected build directory");
}
rmSync(dist, { recursive: true, force: true });

const result = spawnSync(
  process.execPath,
  [compiler, "-p", join(packageRoot, "tsconfig.json")],
  {
    cwd: packageRoot,
    env: process.env,
    stdio: "inherit",
  },
);
if (result.error) throw result.error;
if (result.status !== 0) process.exitCode = result.status ?? 1;
