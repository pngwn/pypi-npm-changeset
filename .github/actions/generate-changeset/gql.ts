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

function get_title(packages: [string, string][]) {
	return packages.length ? `change detected` : `no changes detected`;
}

function create_version_table(packages: [string, string][]) {
	const rendered_packages = packages
		.map(([p, v]) => `|\`${p}\` | \`${v}\` |`)
		.join("\n");

	return `| Package | Version |
|--------|--------|
${rendered_packages}`;
}

function create_package_checklist(
	changed_packages: [string, string][],
	other_packages: string[],
) {
	const changed_packages_list = changed_packages.map(
		([p, v]) => `- [x] \`${p}\``,
	);
	const other_packages_list = other_packages.map((p) => `- [ ] \`${p}\``);

	return `\n#### Select the correct packages:
${changed_packages_list.concat(other_packages_list).join("\n")}

\\-
`;
}

function get_version_interaction_text(manual_version: boolean) {
	return manual_version
		? "enable automatic package selection"
		: "manually select packages to update";
}

export function create_changeset_comment({
	changed_packages,
	changelog,
	manual_version,
	other_packages,
}: {
	changed_packages: [string, string][];
	changelog: string;
	manual_version: boolean;
	other_packages: string[];
}) {
	return `<!-- tag=changesets_gradio -->

###  🦄 ${get_title(changed_packages)}

#### This Pull Request includes changes to the following packages. 

${create_version_table(changed_packages)}
${
	manual_version
		? create_package_checklist(changed_packages, other_packages)
		: ""
}
- [${manual_version ? "x" : " "}] Maintainers can ${
		manual_version ? "de" : " "
	}select this checkbox to ${get_version_interaction_text(manual_version)}.

#### With the following changelog entry.

> ${changelog}

_Maintainers or the PR author can modify the PR title to modify this entry._
<details><summary>

#### Something isn't right</summary>

- Maintainers can change the version label to modify the version bump. 
- If this pull request needs to update multiple packages to different versions or requires a more comprehensive changelog entry, maintainers can [update the changelog file directly]()

</details> `;
}

import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import frontmatter from "remark-frontmatter";
import yaml from "js-yaml";
import { find } from "unist-util-find";
import { ListItem, Text } from "mdast";

const md_parser = unified().use(remarkParse).use(frontmatter).use(remarkGfm);

export function get_frontmatter_versions(
	md: string,
): [string, string][] | false {
	const ast = md_parser.parse(md);
	const frontmatter_node = ast.children.find((n) => n.type === "yaml") as {
		value: string;
	};

	if (frontmatter_node) {
		const versions = (
			Object.entries(yaml.load(frontmatter_node.value)) as [string, string][]
		).map<[string, string]>(([key, value]) => {
			return [key.trim(), value.trim()];
		});

		return versions;
	}

	return false;
}

export function check_for_interaction(md_src: string) {
	if (!md_src) return { manual_version: false };

	console.log(md_src);

	const new_ast = md_parser.parse(md_src);

	console.log(JSON.stringify(new_ast, null, 2));
	const manual_node: ListItem | undefined = find(new_ast, (node) => {
		return (
			node.type === "listItem" &&
			(node as ListItem)?.checked != null &&
			!!find(
				(node as ListItem)?.children[0],
				(inner_node) =>
					(inner_node as Text)?.value?.trim()?.startsWith("Maintainers can "),
			)
		);
	});

	console.log(manual_node);

	return {
		manual_version: !!manual_node?.checked,
	};
}
