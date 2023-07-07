import { getInput, info } from '@actions/core'
import { PackageJSON, getPackagesSync } from "@manypkg/get-packages";
import { context } from "@actions/github"

function run() {
info(JSON.stringify(context, null, 2))
  const { tool, packages, rootPackage, rootDir } = getPackagesSync(process.cwd());

  const python_packages = packages.filter((p) => (p.packageJson as (PackageJSON & {python: boolean})).python);

  console.log(JSON.stringify(python_packages, null, 2));
  const user = getInput("user");
  const passwords = getInput("passwords");
  
  info(user)
  info(passwords);

  const pws = passwords.trim().split("\n").map((p) => p.split(':'));

  info(JSON.stringify(pws, null, 2));

  
}

run()