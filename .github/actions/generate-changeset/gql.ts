export function gql_get_pr(owner: string, repo: string, pr_number: number) {
	return `{
    repository(owner: "${owner}", name: "${repo}") {
      pullRequest(number: ${pr_number}) {
        id
        baseRefName
        headRefName
        baseRefOid
        headRefOid
        closingIssuesReferences(first: 50) {
          nodes {
            labels(after: "", first: 10) {
              nodes {
                name
              }
            }
            id
            body
            number
            title
          }
        }
        labels(first: 10) {
          nodes {
            name
            id
            description
            color
          }
        }
        title
        comments(first: 10) {
          nodes {
            id
            author {
              login
            }
            body
            fullDatabaseId
          }
        }
      }
    }
  }`;
}

function get_title(packages: string[]) {
	return packages.length ? `change detected` : `no changes detected`;
}

function create_version_table(packages: string[], version: string) {
	return packages.map((p) => `|\`${p}\` | \`${version}\` |`).join("\n");
}

export function create_changeset_comment(
	packages: string[],
	version: string,
	changelog: string,
) {
	return `<!-- tag=changesets_gradio -->

###  🦄 ${get_title(packages)}

#### This Pull Request includes changes to the following packages. 

| Package | version |
|--------|--------|
${create_version_table(packages, version)}

- [ ] Maintainers can click this checkbox to manually select packages to update.

#### With the following changelog entry.


> ${changelog}

_Maintainers or the PR author can modify the PR title to modify this entry._
<details><summary>

#### Something isn't right</summary>

- Maintainers can change the version label to modify the version bump. 
- If this pull request needs to update multiple packages to different versions or requires a more comprehensive changelog entry, maintainers can [update the changelog file directly]()

---

- [ ] **Rerun the change detection bot.**
  _This will replace the existing changeset file, reset the version(s) to unknown, set the changelog entry to the PR title, and remove all version labels_

</details> `;
}
