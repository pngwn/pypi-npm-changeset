import { getInput, info, warning } from "@actions/core";
import { exec } from "@actions/exec";
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context } from "@actions/github";
import { request } from "undici";
import { promises as fs } from "fs";
import { join } from "path";
import { getChangedPackagesSinceRef } from "@changesets/git";

const globs_to_ignore = [
	"!**/test/**",
	"!**/*.test.ts",
	"!**/*.test.js",
	"!**/*.spec.js",
	"!**/*.spec.ts",
	"!**/*.stories.svelte",
];

async function run() {
	console.log(context.eventName);
	console.log(context.action);
	console.log(context.payload.action);

	console.log(JSON.stringify(context, null, 2));
	const changed_pkgs = await getChangedPackagesSinceRef({
		cwd: process.cwd(),
		ref: "refs/remotes/origin/main",
		changedFilePatterns: globs_to_ignore,
	});

	info(JSON.stringify(changed_pkgs, null, 2));
}

run();
