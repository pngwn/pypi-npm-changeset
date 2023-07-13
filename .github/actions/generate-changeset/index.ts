import { getInput, setFailed, info, warning } from "@actions/core";
import { exec } from "@actions/exec";
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context, getOctokit } from "@actions/github";
import { promises as fs } from "fs";
import { join } from "path";
import { getChangedPackagesSinceRef } from "@changesets/git";
import {
	gql_get_pr,
	create_changeset_comment,
	get_frontmatter_versions,
	check_for_interaction,
} from "./gql";
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

type PackageJson = Packages["packages"][0]["packageJson"] & {
	python: boolean;
	main_changeset: boolean;
};

async function run() {
	console.log(JSON.stringify(context, null, 2));
	if (context?.payload?.pull_request?.head.ref === "changeset-release/main") {
		info("Release PR. Skipping changeset generation.");
		return;
	}

	const token = getInput("github-token");
	const main_pkg = getInput("main_pkg");
	const octokit = getOctokit(token);

	const response = await octokit.graphql<Record<string, any>>(
		gql_get_pr(context.repo.owner, context.repo.repo, context.issue.number),
	);

	let {
		repository: {
			pullRequest: {
				baseRefName: base_branch_name,
				headRefName: current_branch_name,
				baseRefOid: base_sha,
				headRefOid: head_sha,
				closingIssuesReferences: { nodes: closes },
				labels: { nodes: labels },
				title,
				comments: { nodes: comments },
			},
		},
	} = response;

	const comment = find_comment(comments);
	let version =
		get_version_from_label(labels) || get_version_from_linked_issues(closes);
	let type = get_type_from_label(labels) || get_type_from_linked_issues(closes);

	// const ref =
	// 	context.payload.pull_request?.base?.sha || "refs/remotes/origin/main";

	const changed_pkgs = await getChangedPackagesSinceRef({
		cwd: process.cwd(),
		ref: base_sha,
		changedFilePatterns: dev_only_ignore_globs,
	});

	const { packages: pkgs } = getPackagesSync(process.cwd());

	const main_package_json = pkgs.find(
		(p) => p.packageJson.name === main_pkg,
	) as Packages["packages"][0];

	if (!main_package_json) {
		setFailed(`Could not find main package ${main_pkg}`);
	}

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
	await exec("git", ["diff", "--name-only", base_sha], options);

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

	if (version === "unknown") {
		if (changed_pkgs.length) {
			version = "minor";
			// typ;
		} else if (changed_dependency_files.length) {
			version = "patch";
			title = "Update dependencies.";
		}
	}

	interface PackageSimple {
		name: string;
		add_to_main_changeset: boolean;
	}

	const updated_pkgs = new Set<string>();

	changed_pkgs.forEach((pkg) => {
		updated_pkgs.add(pkg.packageJson.name);
	});

	changed_dependency_files.forEach(([file, pkg]) => {
		updated_pkgs.add(pkg);
		if (
			(pkgs.find((p) => p.packageJson.name === pkg)?.packageJson as PackageJson)
				?.main_changeset
		) {
			updated_pkgs.add(main_pkg);
		}
	});

	let filename = Array.from(changed_files).find((f) =>
		f.startsWith(".changeset/"),
	);

	let old_changeset_content = "";
	let manual_changeset = false;

	if (filename) {
		//check author
		// 	git --no-pager shortlog -p -1 -- .changeset/fresh-seals-lie.md
		let output_data = "";
		const options = {
			listeners: {
				stdout: (data: Buffer) => {
					output_data += data.toString();
				},
				stderr: (data: Buffer) => {
					output_data += data.toString();
				},
			},
		};

		await exec(
			"git",
			["--no-pager", "shortlog", "-p", "-1", "--", filename],
			options,
		);

		const author = output_data.split("\n")[1].trim();

		if (!/github-actions\[bot\]/.test(author)) {
			// do not generate changeset
			warning(
				`Changeset file was edited manuall. Skipping changeset generation.`,
			);
			manual_changeset = true;
		}
		old_changeset_content = (await fs.readFile(filename, "utf-8")).trim();
	} else {
		const id = human_id.humanId({
			separator: "-",
			capitalize: false,
		});

		filename = `.changeset/${id}.md`;
	}

	if (!manual_changeset) {
		const changeset_content = `---
${Array.from(updated_pkgs)
	.map((pkg) => `"${pkg}": ${version}`)
	.join("\n")}
---

${type}:${title}
	`;

		console.log(changeset_content, old_changeset_content);

		if (changeset_content.trim() !== old_changeset_content.trim()) {
			fs.writeFile(filename, changeset_content);

			await exec("git", [
				"config",
				"--global",
				"user.email",
				"41898282+github-actions[bot]@users.noreply.github.com",
			]);
			await exec("git", [
				"config",
				"--global",
				"user.name",
				"github-actions[bot]",
			]);
			await exec("git", ["add", "."]);
			await exec("git", ["commit", "-m", "add changeset"]);
			await exec("git", ["push"]);
		}
	}

	const frontmatter_version = get_frontmatter_versions(old_changeset_content);
	const other_packages = pkgs
		.filter((p) => !p.packageJson.private)
		.map((p) => p.packageJson.name)
		.filter((p) => !updated_pkgs.has(p));

	const { manual_version } =
		context.eventName === "issue_comment"
			? check_for_interaction(context.payload?.comment?.body)
			: { manual_version: false };

	console.log({ manual_version, body: context.payload?.comment?.body });

	const pr_comment_content = create_changeset_comment({
		changed_packages:
			manual_changeset && frontmatter_version
				? frontmatter_version
				: Array.from(updated_pkgs).map((pkg) => [pkg, version]),
		changelog: title,
		manual_version,
		other_packages,
	});

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
		.filter((l) => l.name.startsWith("v:"))?.[0]
		?.name.slice(2)
		.trim();
}

function get_type_from_label(labels: Label[]) {
	if (!labels.length) return undefined;
	return labels
		.filter((l) => l.name.startsWith("t:"))?.[0]
		?.name.slice(2)
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
