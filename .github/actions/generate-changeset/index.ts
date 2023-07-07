import { getInput, info, warning } from "@actions/core";
import { exec } from "@actions/exec";
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context } from "@actions/github";
import { request } from "undici";
import { promises as fs } from "fs";
import { join } from "path";
import { getChangedPackagesSinceRef } from "@changesets/git";

const globs_to_ignore = [
	"!**/test/**/*",
	"!**/*.test.ts",
	"!**/*.test.js",
	"!**/*.spec.js",
	"!**/*.test.ts",
	"!**/*.stories.svelte",
];

async function run() {
	await exec("git", ["show-ref"]);
	const changed_pkgs = await getChangedPackagesSinceRef({
		cwd: process.cwd(),
		ref: "refs/remotes/origin/main",
		changedFilePatterns: globs_to_ignore,
	});

	info(JSON.stringify(changed_pkgs, null, 2));
}

run();
