// @ts-ignore
// import { config } from "dotenv";
const { getPackagesSync } = require("@manypkg/get-packages");
const gh = require("@changesets/get-github-info");
const { getInfo, getInfoFromPullRequest } = gh;
const { tool, packages, rootPackage, rootDir } = getPackagesSync(process.cwd());
// console.log(tool, packages, rootPackage, rootDir)
// config();

function find_packages_dirs(package_name) {
	const _package = packages.find((p) => p.packageJson.name === package_name);
	if (!_package) throw new Error(`Package ${package_name} not found`);
	return [
		_package.dir,
		package_name === "gradio-test-pypi" ? rootDir : null,
	].filter(Boolean);
}

const changelogFunctions = {
	getDependencyReleaseLine: async (
		changesets,
		dependenciesUpdated,
		options,
	) => {
		if (!options.repo) {
			throw new Error(
				'Please provide a repo to this changelog generator like this:\n"changelog": ["@changesets/changelog-github", { "repo": "org/repo" }]',
			);
		}
		if (dependenciesUpdated.length === 0) return "";

		const changesetLink = `- Updated dependencies [${(
			await Promise.all(
				changesets.map(async (cs) => {
					if (cs.commit) {
						let { links } = await getInfo({
							repo: options.repo,
							commit: cs.commit,
						});
						return links.commit;
					}
				}),
			)
		)
			.filter((_) => _)
			.join(", ")}]:`;

		const updatedDepenenciesList = dependenciesUpdated.map(
			(dependency) => `  - ${dependency.name}@${dependency.newVersion}`,
		);

		return [changesetLink, ...updatedDepenenciesList].join("\n");
	},
	getReleaseLine: async (changeset, type, options) => {
		// console.log(changeset, type, options)
		if (!options || !options.repo) {
			throw new Error(
				'Please provide a repo to this changelog generator like this:\n"changelog": ["@changesets/changelog-github", { "repo": "org/repo" }]',
			);
		}

		let prFromSummary;
		let commitFromSummary;
		let usersFromSummary;

		const replacedChangelog = changeset.summary
			.replace(/^\s*(?:pr|pull|pull\s+request):\s*#?(\d+)/im, (_, pr) => {
				let num = Number(pr);
				if (!isNaN(num)) prFromSummary = num;
				return "";
			})
			.replace(/^\s*commit:\s*([^\s]+)/im, (_, commit) => {
				commitFromSummary = commit;
				return "";
			})
			.replace(/^\s*(?:author|user):\s*@?([^\s]+)/gim, (_, user) => {
				usersFromSummary.push(user);
				return "";
			})
			.trim();

		const [firstLine, ...futureLines] = replacedChangelog
			.split("\n")
			.map((l) => l.trimRight());

		console.log(firstLine);

		const links = await (async () => {
			if (prFromSummary !== undefined) {
				let { links } = await getInfoFromPullRequest({
					repo: options.repo,
					pull: prFromSummary,
				});
				if (commitFromSummary) {
					links = {
						...links,
						commit: `[\`${commitFromSummary}\`](https://github.com/${options.repo}/commit/${commitFromSummary})`,
					};
				}
				return links;
			}
			const commitToFetchFrom = commitFromSummary || changeset.commit;
			if (commitToFetchFrom) {
				let { links } = await getInfo({
					repo: options.repo,
					commit: commitToFetchFrom,
				});
				return links;
			}
			return {
				commit: null,
				pull: null,
				user: null,
			};
		})();
		console.log(JSON.stringify(changeset, null, 2));

		const users =
			usersFromSummary && usersFromSummary.length
				? usersFromSummary
						.map(
							(userFromSummary) =>
								`[@${userFromSummary}](https://github.com/${userFromSummary})`,
						)
						.join(", ")
				: links.user;

		const prefix = [
			links.pull === null ? "" : ` ${links.pull}`,
			links.commit === null ? "" : ` ${links.commit}`,
			users === null ? "" : ` Thanks ${users}!`,
		].join("");

		// throw new Error('Not yet')

		console.log({ prefix, firstLine, futureLines, links, usersFromSummary });

		const fs = require("fs");
		const { join } = require("path");

		let lines;
		if (fs.existsSync("./_changelog.json")) {
			lines = JSON.parse(fs.readFileSync("./_changelog.json", "utf-8"));
		} else {
			lines = {
				_handled: [],
			};
		}

		if (lines._handled.includes(changeset.id)) {
			return "done";
		} else {
			lines._handled.push(changeset.id);
		}

		changeset.releases.forEach((release) => {
			if (!lines[release.name])
				lines[release.name] = {
					dirs: find_packages_dirs(release.name),
					current_changelog: "",
					feat: [],
					fix: [],
					highlight: [],
					other: [],
				};

			const changelog_path = join(lines[release.name].dirs[0], "CHANGELOG.md");

			if (fs.existsSync(changelog_path)) {
				lines[release.name].current_changelog = fs
					.readFileSync(changelog_path, "utf-8")
					.replace(`# ${release.name}`, "")
					.trim();
			}

			const [, _type, summary] = changeset.summary.match(
				/^(feat|fix|highlight)\s*:\s*([^]*)/im,
			) || [, false, changeset.summary];

			lines[release.name][_type || "other"].push({
				summary: `${prefix ? `${prefix} -` : ""} ${summary}`,
			});
		});

		// console.log(lines)
		fs.writeFileSync("./_changelog.json", JSON.stringify(lines, null, 2));

		return `\n\n-${prefix ? `${prefix} -` : ""} ${firstLine}\n${futureLines
			.map((l) => `  ${l}`)
			.join("\n")}`;
	},
};

module.exports = changelogFunctions;

//  hello change
