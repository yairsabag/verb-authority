import { spawnSync } from "node:child_process";
import {
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const require = createRequire(import.meta.url);
const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const repositoryRoot = resolve(packageRoot, "..", "..");
const npmCli = process.env.npm_execpath;
if (!npmCli) {
  throw new Error("npm_execpath is required for the package verification");
}

const expectedFiles = [
  "LICENSE",
  "README.md",
  "dist/index.d.ts",
  "dist/index.js",
  "package.json",
].sort();
const expectedBuildFiles = [
  "dist/index.d.ts",
  "dist/index.js",
  "dist/quickstart.d.ts",
  "dist/quickstart.js",
].sort();
const expectedManifest = {
  name: "@verb-authority/node",
  version: "0.0.0-experimental",
  private: true,
  description:
    "Experimental server-side TypeScript per-call argument-authority adapter.",
  license: "Apache-2.0",
  type: "module",
  engines: { node: ">=22" },
  exports: {
    ".": {
      types: "./dist/index.d.ts",
      import: "./dist/index.js",
    },
  },
  types: "./dist/index.d.ts",
  files: ["dist/index.d.ts", "dist/index.js", "LICENSE", "README.md"],
  sideEffects: false,
  scripts: {
    build: "node scripts/build.mjs",
    typecheck: "tsc -p tsconfig.json --noEmit",
    test: "npm run build && node --test test/*.test.mjs",
    quickstart: "npm run build --silent && node dist/quickstart.js",
    "pack:check": "node scripts/verify-package.mjs",
    check: "npm run typecheck && npm run test && npm run pack:check",
  },
  devDependencies: {
    "@types/node": "22.20.1",
    typescript: "7.0.2",
  },
};

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? packageRoot,
    env: options.env ?? process.env,
    encoding: options.encoding,
    stdio: options.stdio,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    if (typeof result.stdout === "string") process.stderr.write(result.stdout);
    if (typeof result.stderr === "string") process.stderr.write(result.stderr);
    throw new Error(`${command} exited with status ${result.status ?? "unknown"}`);
  }
  return result;
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function validateManifest(path, label) {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`${label} is not valid JSON`, { cause: error });
  }
  if (!isDeepStrictEqual(manifest, expectedManifest)) {
    throw new Error(
      `${label} does not match the exact private, dependency-free source-prototype contract`,
    );
  }
}

validateManifest(join(packageRoot, "package.json"), "source package.json");

for (const relativePath of new Set([...expectedFiles, ...expectedBuildFiles])) {
  const source = join(packageRoot, relativePath);
  const stat = lstatSync(source);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`package input is not a regular file: ${relativePath}`);
  }
}
const expectedDistFiles = expectedBuildFiles
  .filter((path) => path.startsWith("dist/"))
  .map((path) => path.slice("dist/".length))
  .sort();
const observedDistEntries = readdirSync(join(packageRoot, "dist"), {
  withFileTypes: true,
});
if (
  observedDistEntries.some((entry) => !entry.isFile()) ||
  JSON.stringify(observedDistEntries.map((entry) => entry.name).sort()) !==
    JSON.stringify(expectedDistFiles)
) {
  throw new Error("dist contains stale, nested, or unexpected build output");
}
if (sha256(join(packageRoot, "LICENSE")) !== sha256(join(repositoryRoot, "LICENSE"))) {
  throw new Error("package LICENSE does not match the repository license");
}

const workspace = mkdtempSync(join(tmpdir(), "verb-authority-node-package-"));
const cache = join(workspace, "npm-cache");
const packed = join(workspace, "packed");
const consumer = join(workspace, "consumer");
mkdirSync(cache);
mkdirSync(packed);
mkdirSync(consumer);
const isolatedEnv = { ...process.env, npm_config_cache: cache };

try {
  const pack = run(
    process.execPath,
    [
      npmCli,
      "pack",
      "--json",
      "--ignore-scripts",
      "--pack-destination",
      packed,
    ],
    { env: isolatedEnv, encoding: "utf8" },
  );
  const records = JSON.parse(pack.stdout);
  if (!Array.isArray(records) || records.length !== 1) {
    throw new Error("npm pack did not return exactly one package record");
  }
  const record = records[0];
  if (
    typeof record.filename !== "string" ||
    basename(record.filename) !== record.filename ||
    !record.filename.endsWith(".tgz")
  ) {
    throw new Error("npm pack returned an unsafe tarball filename");
  }
  const observedFiles = record.files.map((entry) => entry.path).sort();
  if (JSON.stringify(observedFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error(
      `package file allowlist mismatch\nexpected=${JSON.stringify(expectedFiles)}\nobserved=${JSON.stringify(observedFiles)}`,
    );
  }
  if (
    record.files.some(
      (entry) =>
        !Number.isSafeInteger(entry.mode) ||
        (entry.mode & 0o133) !== 0,
    )
  ) {
    throw new Error("package contains an executable or group/world-writable file");
  }
  const tarball = join(packed, record.filename);
  const tarballStat = lstatSync(tarball);
  if (!tarballStat.isFile() || tarballStat.isSymbolicLink()) {
    throw new Error("npm pack did not create one regular tarball");
  }
  const tarballBytes = readFileSync(tarball);
  const shasum = createHash("sha1").update(tarballBytes).digest("hex");
  const integrity = `sha512-${createHash("sha512")
    .update(tarballBytes)
    .digest("base64")}`;
  if (record.shasum !== shasum || record.integrity !== integrity) {
    throw new Error("npm pack hashes do not match the tarball bytes");
  }

  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({ name: "verb-authority-consumer-smoke", private: true, type: "module" }),
    { encoding: "utf8", mode: 0o600 },
  );
  run(
    process.execPath,
    [
      npmCli,
      "install",
      "--offline",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--package-lock=false",
      tarball,
    ],
    { cwd: consumer, env: isolatedEnv, stdio: "inherit" },
  );
  validateManifest(
    join(consumer, "node_modules", "@verb-authority", "node", "package.json"),
    "packed package.json",
  );

  const smokeSource = `
import { createGuardedToolRunner } from "@verb-authority/node";
let invocations = 0;
const runner = createGuardedToolRunner([{
  name: "send_email",
  risk: "write",
  params: [
    { name: "to", authority: "trusted_fixed", type: "string" },
    { name: "body", authority: "outbound_payload", type: "string", maxLength: 2000 },
  ],
  handler: () => { invocations += 1; return { ok: true }; },
}]);
const blocked = await runner.run(
  { name: "send_email", input: { to: "attacker@evil.com", body: "hello" } },
  { trustedArgs: { to: "alice@company.com" } },
);
if (blocked.invoked || invocations !== 0) throw new Error("blocked call reached handler");
const allowed = await runner.run(
  { name: "send_email", input: { to: "alice@company.com", body: "hello" } },
  { trustedArgs: { to: "alice@company.com" } },
);
if (!allowed.resultValidated || invocations !== 1) throw new Error("allowed call did not run exactly once");
`;
  writeFileSync(join(consumer, "smoke.mjs"), smokeSource, {
    encoding: "utf8",
    mode: 0o600,
  });
  const typeSmokeSource = `
import { createGuardedToolRunner, type ExecutionResult } from "@verb-authority/node";
const runner = createGuardedToolRunner([{
  name: "send_email",
  risk: "write",
  params: [
    { name: "to", authority: "trusted_fixed", type: "string" },
    { name: "body", authority: "outbound_payload", type: "string", maxLength: 2000 },
  ],
  handler: async () => ({ ok: true }),
}]);
const execution: Promise<ExecutionResult> = runner.run(
  { name: "send_email", input: { to: "alice@company.com", body: "hello" } },
  { trustedArgs: { to: "alice@company.com" } },
);
void execution;
`;
  writeFileSync(join(consumer, "smoke.ts"), typeSmokeSource, {
    encoding: "utf8",
    mode: 0o600,
  });
  run(process.execPath, [join(consumer, "smoke.mjs")], {
    cwd: consumer,
    stdio: "inherit",
  });

  const typescriptRoot = dirname(require.resolve("typescript/package.json"));
  run(
    process.execPath,
    [
      join(typescriptRoot, "bin", "tsc"),
      "--noEmit",
      "--strict",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--target",
      "ES2022",
      join(consumer, "smoke.ts"),
    ],
    { cwd: consumer, stdio: "inherit" },
  );
  process.stdout.write("verified clean tarball install, ESM import, runtime gate, and TypeScript declarations\n");
} finally {
  rmSync(workspace, { recursive: true, force: true });
}
