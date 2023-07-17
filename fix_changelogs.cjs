const { join } = require("path");
const { readFileSync, existsSync, writeFileSync, unlinkSync } = require("fs");

const { _handled, ...packages } = JSON.parse(
	readFileSync(join(__dirname, "./_changelog.json"), "utf-8"),
);

for (const pkg_name in packages) {
	const { dirs, highlight, feat, fix, current_changelog } = packages[pkg_name];

	const { version, python } = JSON.parse(
		readFileSync(join(dirs[0], "./package.json"), "utf-8"),
	);

	const highlights = highlight.map((h) => `${h.summary}`);
	const features = feat.map((f) => `- ${f.summary}`);
	const fixes = fix.map((f) => `- ${f.summary}`);

	const release_notes = [
		[highlights, "### Highlights"],
		[features, "### Features"],
		[fixes, "### Fixes"],
	]
		.filter(([s], i) => s.length > 0)
		.map(([lines, title]) => {
			if (title === "### Highlights") {
				return `${title}\n\n${lines.join("\n\n")}`;
			} else {
				return `${title}\n\n${lines.join("\n")}`;
			}
		})
		.join("\n\n");

	const new_changelog = `# ${pkg_name}

## ${version}

${release_notes}

${current_changelog}
`.trim();

	dirs.forEach((dir) => {
		writeFileSync(join(dir, "CHANGELOG.md"), new_changelog);
	});

	if (python) {
		writeFileSync(join(dirs[0], "version.txt"), version);
		bump_local_dependents(pkg_name, version);
	}
}

unlinkSync(join(__dirname, "_changelog.json"));

function bump_local_dependents(pkg_to_bump, version) {
	for (const pkg_name in packages) {
		const {
			dirs: [dir],
		} = packages[pkg_name];
		const requirements_path = join(dir, "..", "requirements.txt");
		const requirements = readFileSync(requirements_path, "utf-8").split("\n");

		const pkg_index = requirements.findIndex((line) =>
			line.startsWith(pkg_name),
		);

		if (pkg_index !== -1) {
			requirements[pkg_index] = `${pkg_to_bump}>=${version}`;
			writeFileSync(requirements_path, requirements.join("\n"));
		}
	}
}
