export function gql_get_pr(pr_number: number) {
	return `{
    repository(owner: "pngwn", name: "pypi-npm-changeset") {
      pullRequest(number: ${pr_number}) {
        id
        closingIssuesReferences(first: 50) {
          edges {
            node {
              id
              body
              number
              title
            }
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
          edges {
            node {
              id
              author {
                login
              }
              body
            }
          }
        }
      }
    }
  }`;
}
