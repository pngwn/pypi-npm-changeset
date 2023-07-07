import { getInput, info, warning } from "@actions/core";
import { exec } from "@actions/exec";
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context } from "@actions/github";
import { request } from "undici";
import { promises as fs } from "fs";
import { join } from "path";
import { getChangedPackagesSinceRef } from "@changesets/git";

async function run() {
	const changed_pkgs = await getChangedPackagesSinceRef({
		cwd: process.cwd(),
		ref: "main",
	});

	info(JSON.stringify(changed_pkgs, null, 2));
}

run();
