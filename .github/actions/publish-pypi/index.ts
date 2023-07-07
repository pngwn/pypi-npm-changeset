import { getInput, info, warning } from "@actions/core";
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context } from "@actions/github";
import { request } from "undici";

async function run() {
	const { tool, packages, rootPackage, rootDir } = getPackagesSync(
		process.cwd()
	);
	type PackageJson = Packages["packages"][0]["packageJson"];
	const python_packages = packages.filter(
		(p) => (p.packageJson as PackageJson & { python: boolean }).python
	);

	console.log(JSON.stringify(python_packages, null, 2));
	const user = getInput("user");
	const passwords = getInput("passwords");

	await Promise.all(
		python_packages.map(async (p) => {
			const package_name = p.packageJson.name;
			const version = p.packageJson.version;
			info(`Checking if ${package_name}@${version} exists on PyPI`);

			const exists = await check_version_exists(package_name, version);

			if (exists) {
				warning(
					`${package_name}@${version} already exists on PyPI. Aborting publish.`
				);
				return false;
			}

			info(`Publishing ${package_name}@${version} to PyPI`);
			return true;
		})
	);

	info(user);
	info(passwords);

	const pws = passwords
		.trim()
		.split("\n")
		.map((p) => p.split(":"));

	info(JSON.stringify(pws, null, 2));
}

run();

async function check_version_exists(package_name: string, version: string) {
	const { statusCode, body } = await request(
		`https://pypi.org/pypi/${package_name}/json`
	);

	if (statusCode !== 200) {
		warning(`Could not find package: ${package_name} on PyPI.`);
		return false;
	}

	const data = await body.json();

	return version in data.releases;
}
