# Recommended Rules

This directory documents every rule evaluated by
`gh secure-kit recommended check` / `gh secure-kit recommended apply`,
similar in spirit to [ShellCheck's wiki
pages](https://www.shellcheck.net/wiki/). Each rule's ID also links to the
equivalent [microsoft/ghqr](https://github.com/microsoft/ghqr) rule, if any.

Run `gh secure-kit recommended explain <ID>` to view a rule's documentation
from the command line, or `gh secure-kit recommended list` to see the full
catalog with severity, scope, and fixability.

## Repository rules

| Rule | Severity | Fixable | Title |
|---|---|---|---|
| [GSK101](GSK101.md) | High | Yes | Dependabot alerts not enabled |
| [GSK102](GSK102.md) | Medium | No | Dependabot enabled but no dependabot.yml found |
| [GSK103](GSK103.md) | Low | Yes | No SECURITY.md file found |
| [GSK104](GSK104.md) | Medium | Yes | No CODEOWNERS file found |
| [GSK105](GSK105.md) | High | Yes | Code scanning (CodeQL) not configured |
| [GSK106](GSK106.md) | High | Yes | Secret scanning not enabled |
| [GSK107](GSK107.md) | High | Yes | Secret scanning push protection not enabled |
| [GSK108](GSK108.md) | Medium | Yes | Private vulnerability reporting not enabled |
| [GSK109](GSK109.md) | Medium | Yes | Dependabot security updates not enabled |
| [GSK110](GSK110.md) | Critical | No | No branch protection configured on default branch |
| [GSK111](GSK111.md) | Critical | No | No approving reviews required before merge |
| [GSK112](GSK112.md) | Medium | No | Only 1 approving review required |
| [GSK113](GSK113.md) | High | No | Stale reviews not dismissed on new commits |
| [GSK114](GSK114.md) | Medium | No | Code owner review not required |
| [GSK115](GSK115.md) | High | No | Strict status checks not enabled |
| [GSK116](GSK116.md) | High | No | No required status checks configured |
| [GSK117](GSK117.md) | Critical | No | Force pushes allowed on protected branch |
| [GSK118](GSK118.md) | Medium | No | Signed commits not required |
| [GSK119](GSK119.md) | High | No | Excessive admin collaborators |
| [GSK120](GSK120.md) | Medium | No | Direct collaborators instead of teams |
| [GSK121](GSK121.md) | High | No | Deploy keys with write access |
| [GSK122](GSK122.md) | Medium | No | Unverified deploy keys |
| [GSK123](GSK123.md) | Medium | No | Repository has no description |
| [GSK124](GSK124.md) | Low | No | Repository has no topics |
| [GSK125](GSK125.md) | Low | Yes | Auto-delete branches on merge not enabled |
| [GSK126](GSK126.md) | Low | Yes | Issues and Discussions both disabled |
| [GSK127](GSK127.md) | Low | No | Repository appears dormant but is not archived |

## Organization rules

| Rule | Severity | Fixable | Title |
|---|---|---|---|
| [GSK501](GSK501.md) | Critical | No | Two-factor authentication not required for members |
| [GSK502](GSK502.md) | Medium | Yes | Web commit signoff not required |
| [GSK503](GSK503.md) | High | Yes | Default repository permission is admin or write |
| [GSK504](GSK504.md) | Medium | Yes | Members can create public repositories |
| [GSK505](GSK505.md) | Medium | No | No security manager team assigned |
| [GSK506](GSK506.md) | High | Yes | Actions allows all third-party actions and reusable workflows |
