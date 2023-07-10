import { getInput, info, warning } from "@actions/core";
import { exec } from "@actions/exec";
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context, getOctokit } from "@actions/github";
import { request } from "undici";
import { promises as fs } from "fs";
import { join } from "path";
import { getChangedPackagesSinceRef } from "@changesets/git";
import { gql_get_pr } from "./gql";

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

type PackageJson = Packages["packages"][0]["packageJson"] & { python: boolean };

async function run() {
	console.log(context.eventName);
	console.log(context.action);
	console.log(context.payload.action);

	const token = getInput("github-token");

	const octokit = getOctokit(token);

	// const comments = await octokit.rest.issues.listComments({
	// 	owner: context.repo.owner,
	// 	repo: context.repo.repo,
	// 	issue_number: context.issue.number,
	// });

	// console.log(comments);

	const response = await octokit.graphql<Record<string, any>>(
		gql_get_pr(context.issue.number),
	);
	// console.log(JSON.stringify(response, null, 2));
	// console.log(JSON.stringify(response, null, 2));
	// console.log(response?.repository);
	// console.log(response?.repository?.pullRequest);
	// console.log(response?.repository?.pullRequest?.closingIssuesReferences);

	const {
		repository: {
			pullRequest: {
				closingIssuesReferences: { edges: closes },
				labels: { nodes: labels },
				title,
				comments: { nodes: comments },
			},
		},
	} = response;

	const the_comment = comments.find((comment) => {
		const body = comment.body;
		return body?.includes("<!-- tag=changesets_gradio -->");
	});

	console.log(JSON.stringify(the_comment, null, 2));

	if (the_comment) {
		console.log("found comment");
	} else {
		console.log("no comment");
	}

	console.log(JSON.stringify(closes, null, 2));
	console.log(JSON.stringify(labels, null, 2));
	console.log(title);

	if (
		context.payload.action === "opened" ||
		context.payload.action === "edited"
	) {
		// TODO: check if context.payload.changes.title is defined
		// if so load the changset file and check if the text is the same as context.payload.changes.title
		// if not then the changelog file has been manually edited, abort
		// else change the changelog text to the PR title in context.pull_request.title
	}

	if (context.payload.action === "closed") {
		// do we need to do anything here?
	}

	if (
		context.payload.action === "opened" ||
		context.payload.action === "synchronize"
	) {
		const ref =
			context.payload.pull_request?.base?.sha || "refs/remotes/origin/main";

		const changed_pkgs = await getChangedPackagesSinceRef({
			cwd: process.cwd(),
			ref,
			changedFilePatterns: dev_only_ignore_globs,
		});

		const { packages: pkgs } = getPackagesSync(process.cwd());

		const dependency_files = pkgs.map(({ packageJson, relativeDir }) => {
			if ((packageJson as PackageJson).python) {
				return [join(relativeDir, "..", "requirements.txt"), packageJson.name];
			} else {
				return [join(relativeDir, "package.json"), packageJson.name];
			}
		});

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

		const changed_files = output
			.split("\n")
			.map((s) => s.trim())
			.filter(Boolean)
			.reduce<Set<string>>((acc, next) => {
				acc.add(next);
				return acc;
			}, new Set());

		const changed_dependency_files = dependency_files.filter(([f]) =>
			changed_files.has(f),
		);
		console.log(changed_dependency_files);
		info(JSON.stringify(changed_pkgs, null, 2));
	}

	if (
		context.payload.action === "labeled" ||
		context.payload.action === "unlabeled"
	) {
	}
	// console.log(JSON.stringify(context, null, 2));

	// const changed_dependencies = await getChangedPackagesSinceRef({
	// 	cwd: process.cwd(),
	// 	ref,
	// 	changedFilePatterns: dev_only_ignore_globs,
	// });
}

run();

/**
 * first run === no PR comment
 * - Get labels for PR
 *   - if v:* apply as version
 * - Else get linked issues from PR body
 *   - if linked issues, check labels (bug/feature)
 *   - if bug, patch
 *   - if feature, minor
 *   - if no linked issues, unknown
 * - Get the changed packages from the PR
 *   - separate dependency updates from changes
 *   - dependency update = patch + default title
 *   - changes = version from above + title from PR title
 * 	 - if no changes, apply no-changes label
 * - if non-depednecy change, get the changelog text from the PR title
 */

// package(s) - version - type - changelog
