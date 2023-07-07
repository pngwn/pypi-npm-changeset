import { getInput, info } from '@actions/core'

function run() {
  const packages = getInput("packages");
  info(packages);

  const parsed = JSON.parse(packages);

  info(parsed);
  info(JSON.stringify(parsed, null, 2));
}

run()