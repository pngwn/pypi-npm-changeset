export function gql_get_pr(owner: string, repo: string, pr_number: number) {
	return `{
    repository(owner: ${owner}, name: ${repo}) {
      pullRequest(number: ${pr_number}) {
        id
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
          }
        }
      }
    }
  }`;
}
