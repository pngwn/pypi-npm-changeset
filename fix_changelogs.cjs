const { join } = require('path');
const { readFileSync, existsSync, writeFileSync, unlinkSync } = require('fs');


const changeset  = JSON.parse(readFileSync(join(__dirname, './_changelog.json'), 'utf-8'));
// console.log(c)

for (const pkg_name in changeset) {
    const { dirs, highlight, feat, fix, other, current_changelog } = changeset[pkg_name];
    const {version, python}  = JSON.parse(readFileSync(join(dirs[0], './package.json'), 'utf-8'));
    const changelog_path = join(dirs[0], 'CHANGELOG.md');

    
    



    const highlights = highlight.map((h) => `${h.summary}`);
    const features = feat.map((f) => `- ${f.summary}`);
    const fixes = fix.map((f) => `- ${f.summary}`);
    const others = other.map((o) => `- ${o.summary}`);

    const release_notes = [[highlights, "### Highlights"], [features, "### Features"], [fixes, "### Fixes"], [others, "### Other changes"]]
      .filter(([s]) => s.length > 0).map(([lines, title]) => `${title}\n\n${lines.join("\n")}`).join("\n\n");

    console.log(release_notes)
    const new_changelog = `# ${pkg_name}

## ${version}

${release_notes}

${current_changelog}
`.trim();

// console.log(new_changelog)

 dirs.forEach(dir => {
  writeFileSync(join(dir, 'CHANGELOG.md'), new_changelog);
 });

 if (python) {
  writeFileSync(join(dirs[0], 'version.txt'), version);
 }
}

unlinkSync(join(__dirname, '_changelog.json'));
