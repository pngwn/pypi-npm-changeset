import { getInput, info, warning } from "@actions/core";
import { exec } from "@actions/exec";
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context, getOctokit } from "@actions/github";
import { request } from "undici";
import { promises as fs } from "fs";
import { join } from "path";
import { getChangedPackagesSinceRef } from "@changesets/git";
import { gql_get_pr, create_changeset_comment } from "./gql";
import * as human_id from "human-id";

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
	console.log(human_id);
	// console.log(JSON.stringify(context, null, 2));
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

	console.log({ comments, labels: JSON.stringify(labels, null, 2), closes });

	const comment = find_comment(comments);
	let version =
		get_version_from_label(labels) || get_version_from_linked_issues(closes);
	let type = get_type_from_label(labels) || get_type_from_linked_issues(closes);

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
			// typ;
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
	console.log({ type });

	const pr_comment_content = create_changeset_comment(
		Array.from(updated_pkgs),
		version,
		title,
	);

	let filename = Array.from(changed_files).find((f) =>
		f.startsWith(".changeset/"),
	);

	let old_changeset_content = "";
	if (filename) {
		old_changeset_content = (await fs.readFile(filename, "utf-8")).trim();
	} else {
		const id = human_id.humanId({
			separator: "-",
			capitalize: false,
		});

		filename = `.changeset/${id}.md`;
	}

	const changeset_content = `---
${Array.from(updated_pkgs)
	.map((pkg) => `"${pkg}": ${version}`)
	.join("\n")}
---

${type}:${title}
	`;

	if (changeset_content !== old_changeset_content) {
		fs.writeFile(filename, changeset_content);

		await exec("git", ["config", "--global", "user.email", "you@example.com"]);
		await exec("git", ["config", "--global", "user.name", "my name"]);
		await exec("git", ["add", "."]);
		await exec("git", ["commit", "-m", "add changeset"]);
		await exec("git", ["push"]);
	}

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

function get_version_from_label(labels: Label[]) {
	if (!labels.length) return undefined;
	return labels
		.filter((l) => l.name.startsWith("v:"))[0]
		.name.slice(2)
		.trim();
}

function get_type_from_label(labels: Label[]) {
	if (!labels.length) return undefined;
	return labels
		.filter((l) => l.name.startsWith("t:"))[0]
		.name.slice(2)
		.trim();
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

function get_version_from_linked_issues(closes: ClosesLink[]) {
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

function get_type_from_linked_issues(closes: ClosesLink[]) {
	let type = "fix";
	closes.forEach((c) => {
		const labels = c.labels.nodes.map((l) => l.name);
		if (labels.includes("bug") && type !== "feat") {
			type = "fix";
		} else if (labels.includes("enhancement")) {
			type = "feat";
		}
	});

	return type;
}
