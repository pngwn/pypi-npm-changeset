import { getInput, info, warning } from "@actions/core";
import { exec } from "@actions/exec";
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context, getOctokit } from "@actions/github";
import { request } from "undici";
import { promises as fs } from "fs";
import { join } from "path";
import { getChangedPackagesSinceRef } from "@changesets/git";
import { gql_get_pr, create_changeset_comment } from "./gql";

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
	console.log(JSON.stringify(context, null, 2));
	console.log(context.eventName);
	console.log(context.payload.action);

	const token = getInput("github-token");
	const octokit = getOctokit(token);

	const response = await octokit.graphql<Record<string, any>>(
		gql_get_pr(context.repo.owner, context.repo.repo, context.issue.number),
	);

	let {
		repository: {
			pullRequest: {
				closingIssuesReferences: { nodes: closes },
				labels: { nodes: labels },
				title,
				comments: { nodes: comments },
			},
		},
	} = response;

	const comment = find_comment(comments);
	let version = find_version_label(labels) || get_version_bump(closes);

	// console.log(comment, version_label);

	// console.log(title);

	// if (
	// 	context.payload.action === "opened" ||
	// 	context.payload.action === "edited"
	// ) {
	// TODO: check if context.payload.changes.title is defined
	// if so load the changset file and check if the text is the same as context.payload.changes.title
	// if not then the changelog file has been manually edited, abort
	// else change the changelog text to the PR title in context.pull_request.title
	// }

	// if (context.payload.action === "closed") {
	// 	// do we need to do anything here?
	// }

	// if (
	// 	context.payload.action === "opened" ||
	// 	context.payload.action === "synchronize"
	// ) {
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
	console.log("changed deps", changed_dependency_files);
	info("changed_pkgs");
	info(JSON.stringify(changed_pkgs, null, 2));

	if (version === "unknown") {
		if (changed_pkgs.length) {
			version = "minor";
		} else if (changed_dependency_files.length) {
			version = "patch";
			title = "Update dependencies.";
		}
	}

	const updated_pkgs = new Set<string>();

	changed_pkgs.forEach((pkg) => {
		updated_pkgs.add(pkg.packageJson.name);
	});

	changed_dependency_files.forEach(([file, pkg]) => {
		updated_pkgs.add(pkg);
	});

	console.log({ title });
	console.log({ updated_pkgs });
	console.log({ version });
	console.log({ type: "TODO" });
	// }

	// if (
	// 	context.payload.action === "labeled" ||
	// 	context.payload.action === "unlabeled"
	// ) {
	// }
	// console.log(JSON.stringify(context, null, 2));

	// const changed_dependencies = await getChangedPackagesSinceRef({
	// 	cwd: process.cwd(),
	// 	ref,
	// 	changedFilePatterns: dev_only_ignore_globs,
	// });

	const pr_comment_content = create_changeset_comment(
		Array.from(updated_pkgs),
		version,
		title,
	);

	const changeset_content = `---
${Array.from(updated_pkgs)
	.map((pkg) => `- ${pkg}: ${version}`)
	.join("\n")}
---

${title}
	`;

	console.log(comment);
	if (comment) {
		await octokit.rest.issues.updateComment({
			owner: context.repo.owner,
			repo: context.repo.repo,
			comment_id: parseInt(comment.fullDatabaseId),
			body: pr_comment_content,
		});
	} else {
		await octokit.rest.issues.createComment({
			owner: context.repo.owner,
			repo: context.repo.repo,
			issue_number: context.issue.number,
			body: pr_comment_content,
		});
	}

	fs.writeFile(".changeset/changeset.md", changeset_content);
	const _ref = getInput("ref");

	// git config --global user.email "you@example.com"
	// git config --global user.name "Your Name"

	await exec("git", ["config", "--global", "user.email", "you@example.com"]);
	await exec("git", ["config", "--global", "user.name", "my name"]);
	await exec("git", ["add", "."]);
	await exec("git", ["commit", "-m", "add changeset"]);
	await exec("git", ["push", "origin", context.payload.pull_request?.head.ref]);

	// context.payload.pull_request.
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

interface Label {
	name: string;
	id: string;
}

function find_version_label(labels: Label[]) {
	return labels.filter((l) => l.name.startsWith("v:"))[0].name.slice(2);
}

interface Comment {
	id: string;
	body: string;
	author: {
		login: string;
	};
	fullDatabaseId: string;
}

function find_comment(comments: Comment[]) {
	const comment = comments.find((comment) => {
		const body = comment.body;
		return body?.includes("<!-- tag=changesets_gradio -->");
	});

	return comment
		? {
				...comment,
				author: comment.author.login,
		  }
		: undefined;
}

interface ClosesLink {
	body: string;
	number: number;
	title: string;
	labels: {
		nodes: { name: string }[];
	};
}

function get_version_bump(closes: ClosesLink[]) {
	let version = "unknown";
	closes.forEach((c) => {
		const labels = c.labels.nodes.map((l) => l.name);
		if (labels.includes("bug") && version !== "minor") {
			version = "patch";
		} else if (labels.includes("enhancement")) {
			version = "minor";
		}
	});

	return version;
}
