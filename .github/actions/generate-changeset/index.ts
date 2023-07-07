import { getInput, info, warning } from "@actions/core";
import { exec } from "@actions/exec";
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context } from "@actions/github";
import { request } from "undici";
import { promises as fs } from "fs";
import { join } from "path";
import { getChangedPackagesSinceRef } from "@changesets/git";

const dev_only_ignore_globs = [
	"!**/test/**",
	"!**/*.test.ts",
	"!**/*.test.js",
	"!**/*.spec.js",
	"!**/*.spec.ts",
	"!**/*.stories.svelte",
	"!**/package.json",
	"!**/requirements.txt",
];

const dependency_globs = ["**/package.json", "**/requirements.txt"];
type PackageJson = Packages["packages"][0]["packageJson"] & { python: boolean };

async function run() {
	console.log(context.eventName);
	console.log(context.action);
	console.log(context.payload.action);

	if (context.payload.action === "edited") {
		// TODO: check if context.payload.changes.title is defined
		// if so load the changset file and check if the text is the same as context.payload.changes.title
		// if not then the changelog file has been manually edited, abort
		// else change the changelog text to the PR title in context.pull_request.title
	}

	// console.log(JSON.stringify(context, null, 2));
	const changed_pkgs = await getChangedPackagesSinceRef({
		cwd: process.cwd(),
		ref: "refs/remotes/origin/main",
		changedFilePatterns: dev_only_ignore_globs,
	});

	const { packages: pkgs } = getPackagesSync(process.cwd());

	const dependency_files = pkgs.map(({ dir, packageJson, relativeDir }) => {
		if ((packageJson as PackageJson).python) {
			return join(relativeDir, "..", "requirements.txt");
		} else {
			return join(relativeDir, "package.json");
		}
	});

	const ref =
		context.payload.pull_request?.base?.sha || "refs/remotes/origin/main";
	let output = "";
	let error = "";

	const options = {
		listeners: {
			stdout: (data: Buffer) => {
				output += data.toString();
			},
			stderr: (data: Buffer) => {
				error += data.toString();
			},
		},
	};
	await exec("git", ["diff", "--name-only", ref], options);

	console.log(
		output,
		error,
		output
			.split("\n")
			.map((s) => s.trim())
			.filter(Boolean),
	);

	console.log(dependency_files);

	// const changed_dependencies = await getChangedPackagesSinceRef({
	// 	cwd: process.cwd(),
	// 	ref,
	// 	changedFilePatterns: dev_only_ignore_globs,
	// });

	info(JSON.stringify(changed_pkgs, null, 2));
}

run();
