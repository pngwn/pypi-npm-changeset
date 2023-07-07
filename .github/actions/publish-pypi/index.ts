import { getInput, info, warning } from "@actions/core";
import { exec } from "@actions/exec";
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context } from "@actions/github";
import { request } from "undici";
import { promises as fs } from "fs";

import * as files from "./requirements";

async function run() {
	const { tool, packages, rootPackage, rootDir } = getPackagesSync(
		process.cwd(),
	);
	type PackageJson = Packages["packages"][0]["packageJson"];
	const python_packages = packages.filter(
		(p) => (p.packageJson as PackageJson & { python: boolean }).python,
	);

	console.log(JSON.stringify(python_packages, null, 2));
	const user = getInput("user");
	const passwords = getInput("passwords");

	const packages_to_publish = (
		await Promise.all(
			python_packages.map(async (p) => {
				const package_name = p.packageJson.name;
				const version = p.packageJson.version;

				const exists = await check_version_exists(package_name, version);

				if (exists) {
					warning(
						`${package_name}@${version} already exists on PyPI. Aborting publish.`,
					);
					return false;
				}

				info(`Publishing ${package_name}@${version} to PyPI`);
				return p;
			}),
		)
	).filter(Boolean) as Packages["packages"];

	info("Installing prerequisites.");
	await fs.mkdir("_action_temp/requirements", { recursive: true });
	for (const [name, content] of Object.values(files)) {
		console.log(name, content);
		await fs.writeFile(`_action_temp/requirements/${name}`, content);
	}

	const _files = await fs.readdir("_action_temp");
	console.log(_files);
	// await Promise.all()
	await exec(
		"pip",
		[
			"install",
			"twine",
			"--user",
			"--upgrade",
			"--no-cache-dir",
			"-r",
			"_action_temp/requirements/runtime-prerequisites.in",
		],
		{
			env: {
				...process.env,
				PIP_CONSTRAINT: "_action_temp/requirements/runtime-prerequisites.txt",
			},
		},
	);

	await exec(
		"pip",
		[
			"install",
			"--user",
			"--upgrade",
			"--no-cache-dir",
			"--prefer-binary",
			"-r",
			"_action_temp/requirements/runtime.in",
		],
		{
			env: {
				...process.env,
				PIP_CONSTRAINT: "_action_temp/requirements/runtime.txt",
			},
		},
	);

	info(user);
	info(passwords);

	const pws = passwords
		.trim()
		.split("\n")
		.map((p) => p.split(":"));

	info(JSON.stringify(pws, null, 2));

	// TODO: remove `_action_temp` directory at end of run
}

run();

async function check_version_exists(package_name: string, version: string) {
	const { statusCode, body } = await request(
		`https://pypi.org/pypi/${package_name}/json`,
	);

	if (statusCode !== 200) {
		warning(`Could not find package: ${package_name} on PyPI.`);
		return false;
	}

	const data = await body.json();

	return version in data.releases;
}
