#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(scriptDir, '..');
const repoDir = resolve(packageDir, '..');
const packageJsonPath = join(packageDir, 'package.json');
const releaseDir = join(packageDir, 'release');

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: options.cwd ?? packageDir,
    encoding: 'utf8',
    stdio: options.stdio ?? 'pipe',
  }).trim();
}

function runVisible(command, args, options = {}) {
  execFileSync(command, args, {
    cwd: options.cwd ?? packageDir,
    stdio: 'inherit',
  });
}

function parseArgs(argv) {
  const args = {
    bump: 'patch',
    dryRun: false,
  };

  for (const arg of argv) {
    if (arg === '--dry-run') args.dryRun = true;
    else if (arg === 'patch' || arg === 'minor' || arg === 'major') args.bump = arg;
    else if (arg.startsWith('--version=')) args.version = arg.slice('--version='.length);
    else {
      throw new Error(`Unknown release argument: ${arg}`);
    }
  }

  return args;
}

function bumpVersion(current, bump) {
  const parts = current.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 3 || parts.some((part) => Number.isNaN(part))) {
    throw new Error(`Cannot bump non-semver version: ${current}`);
  }

  const [major, minor, patch] = parts;
  if (bump === 'major') return `${major + 1}.0.0`;
  if (bump === 'minor') return `${major}.${minor + 1}.0`;
  return `${major}.${minor}.${patch + 1}`;
}

function assertCleanGit() {
  const status = run('git', ['status', '--porcelain'], { cwd: repoDir });
  if (status !== '') {
    throw new Error('Git working tree is not clean. Commit or stash changes before releasing.');
  }
}

const args = parseArgs(process.argv.slice(2));
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
const nextVersion = args.version ?? bumpVersion(packageJson.version, args.bump);
const tag = `bwh-auth-v${nextVersion}`;
const assetName = `bwh-auth-${nextVersion}.tgz`;
const assetPath = join(releaseDir, assetName);

assertCleanGit();

try {
  run('git', ['rev-parse', '--verify', tag], { cwd: repoDir });
  throw new Error(`Tag already exists: ${tag}`);
} catch (error) {
  if (error.status === 0) throw error;
}

packageJson.version = nextVersion;
writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);

runVisible('pnpm', ['install', '--lockfile-only'], { cwd: repoDir });
runVisible('pnpm', ['typecheck'], { cwd: packageDir });
runVisible('pnpm', ['build'], { cwd: packageDir });

if (existsSync(releaseDir)) {
  rmSync(releaseDir, { recursive: true, force: true });
}
mkdirSync(releaseDir, { recursive: true });

runVisible('pnpm', ['pack', '--pack-destination', releaseDir], { cwd: packageDir });
const packedFiles = readdirSync(releaseDir).filter((fileName) => fileName.endsWith('.tgz'));
if (packedFiles.length !== 1) {
  throw new Error(`Expected exactly one packed tarball, found ${packedFiles.length}.`);
}
const packedPath = join(releaseDir, packedFiles[0]);

if (packedPath !== assetPath) {
  rmSync(assetPath, { force: true });
  renameSync(packedPath, assetPath);
}

if (args.dryRun) {
  console.log(`Dry run complete: ${assetPath}`);
  console.log(`Release tag would be: ${tag}`);
  process.exit(0);
}

// Pushing the tag is the trigger: the release workflow
// (.github/workflows/release.yml) builds, publishes bwh-auth to npm, and creates
// the GitHub release with the packed tarball. Local pack above is validation only.
runVisible('git', ['add', 'ui/package.json', 'pnpm-lock.yaml'], { cwd: repoDir });
runVisible('git', ['commit', '-m', `Release bwh-auth v${nextVersion}`], { cwd: repoDir });
runVisible('git', ['tag', '-s', '-a', tag, '-m', `Release bwh-auth v${nextVersion}`], { cwd: repoDir });
runVisible('git', ['push', 'origin', 'main'], { cwd: repoDir });
runVisible('git', ['push', 'origin', tag], { cwd: repoDir });

console.log('');
console.log(`Tagged and pushed: ${tag}`);
console.log('The release workflow will publish bwh-auth to npm and create the GitHub release.');
