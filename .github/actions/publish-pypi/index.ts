import { getInput, info } from '@actions/core'

function run() {
  const user = getInput("user");
  const passwords = getInput("packages");
  info(user)
  info(passwords);

  const pws = passwords.trim().split("\n").map((p) => p.split(':'));

  info(JSON.stringify(pws, null, 2));

  
}

run()