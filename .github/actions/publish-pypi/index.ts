import { getInput, info, warning } from '@actions/core'
import { type Packages, getPackagesSync } from "@manypkg/get-packages";
import { context } from "@actions/github"
import { request } from 'undici'

async function run() {
info(JSON.stringify(context, null, 2))
  const { tool, packages, rootPackage, rootDir } = getPackagesSync(process.cwd());
  type PackageJson = Packages["packages"][0]["packageJson"]
  const python_packages = packages.filter((p) => (p.packageJson as (PackageJson & {python: boolean})).python);

  console.log(JSON.stringify(python_packages, null, 2));
  const user = getInput("user");
  const passwords = getInput("passwords");

  await Promise.all(python_packages.map(async(p) => {
    const package_name = p.packageJson.name;
    const version = p.packageJson.version;
    info(`Checking if ${package_name} version ${version} exists on PyPI`);
    await check_version_exists(package_name);
  }))
  
  info(user)
  info(passwords);

  const pws = passwords.trim().split("\n").map((p) => p.split(':'));

  info(JSON.stringify(pws, null, 2));

  
}

run()

async function check_version_exists(package_name: string) {
 const { statusCode, body } = await request(`https://pypi.org/pypi/${package_name}/json`);

 if (statusCode !== 200) {
  warning(`Could not find package: ${package_name} on PyPI.`)
  return false;
 }

 const data = await body.json();
console.log(JSON.stringify(data, null, 2));
 console.log(JSON.stringify(data.releases, null, 2));
//   try:
//   with urllib.request.urlopen(f"https://pypi.org/pypi/{pypi_module}/json") as url:
//       print(url)
//       releases = json.load(url)["releases"]
// except urllib.error.HTTPError as e:
//   if e.code == 404:
//     print(f"Module {pypi_module} does not exist on PyPI")


// if releases and version in releases:
//     print(f"Version {version} already exists on PyPI")
//     sys.exit(1)
// else:
//     print(f"Version {version} does not exist on PyPI")
}