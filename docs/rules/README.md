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
| [GSK105](GSK105.md) | High | Yes | Code scanning default setup not configured |
| [GSK106](GSK106.md) | High | Yes | Secret scanning not enabled |
| [GSK107](GSK107.md) | High | Yes | Secret scanning push protection not enabled |
| [GSK108](GSK108.md) | Medium | Yes | Private vulnerability reporting not enabled |
| [GSK109](GSK109.md) | Medium | Yes | Dependabot security updates not enabled |
| [GSK110](GSK110.md) | Critical | Yes | No branch protection configured on default branch |
| [GSK111](GSK111.md) | Critical | Yes | No approving reviews required before merge |
| [GSK112](GSK112.md) | Medium | Yes | Only 1 approving review required |
| [GSK113](GSK113.md) | High | Yes | Stale reviews not dismissed on new commits |
| [GSK114](GSK114.md) | Medium | Yes | Code owner review not required |
| [GSK115](GSK115.md) | High | Yes | Strict status checks not enabled |
| [GSK116](GSK116.md) | High | No | No required status checks configured |
| [GSK117](GSK117.md) | Critical | Yes | Force pushes allowed on protected branch |
| [GSK118](GSK118.md) | Medium | Yes | Signed commits not required |
| [GSK119](GSK119.md) | High | No | Excessive admin collaborators |
| [GSK120](GSK120.md) | Medium | No | Direct collaborators instead of teams |
| [GSK121](GSK121.md) | High | No | Deploy keys with write access |
| [GSK122](GSK122.md) | Medium | No | Unverified deploy keys |
| [GSK123](GSK123.md) | Medium | No | Repository has no description |
| [GSK124](GSK124.md) | Low | No | Repository has no topics |
| [GSK125](GSK125.md) | Low | Yes | Auto-delete branches on merge not enabled |
| [GSK126](GSK126.md) | Low | Yes | Issues and Discussions both disabled |
| [GSK127](GSK127.md) | Low | No | Repository appears dormant but is not archived |
| [GSK128](GSK128.md) | High | Yes | Branch deletion allowed on protected branch |
| [GSK129](GSK129.md) | Low | Yes | Conversation resolution not required before merge |
| [GSK130](GSK130.md) | Info | No | Linear history not required |
| [GSK131](GSK131.md) | Medium | No | Branch protection can be bypassed |
| [GSK132](GSK132.md) | High | Yes | GITHUB_TOKEN default permissions are read-write |
| [GSK133](GSK133.md) | High | Yes | Actions can approve pull requests |
| [GSK134](GSK134.md) | High | Yes | Fork pull request workflows run without maintainer approval |
| [GSK135](GSK135.md) | Medium | No | Environment with secrets has no required reviewers configured |
| [GSK136](GSK136.md) | High | Yes | Environment with secrets allows self-review |
| [GSK137](GSK137.md) | Medium | No | Environment deployment branch policy allows all branches |
| [GSK138](GSK138.md) | High | Yes | Actions SHA pinning not required |
| [GSK139](GSK139.md) | Medium | Yes | Immutable releases not enabled |
| [GSK140](GSK140.md) | Medium | Yes | Tags are not protected by a tag ruleset |
| [GSK141](GSK141.md) | High | Yes | Private fork pull request workflows receive write tokens or secrets |
| [GSK142](GSK142.md) | Medium | Yes | Forking allowed on private or internal repository |
| [GSK143](GSK143.md) | Info | No | No push ruleset restricting pushed files |
| [GSK144](GSK144.md) | High | No | Webhook uses insecure transport |
| [GSK145](GSK145.md) | Medium | No | Webhook has no secret |

## Organization rules

| Rule | Severity | Fixable | Title |
|---|---|---|---|
| [GSK501](GSK501.md) | Critical | No | Two-factor authentication not required for members |
| [GSK502](GSK502.md) | Medium | Yes | Web commit signoff not required |
| [GSK503](GSK503.md) | High | Yes | Default repository permission is admin or write |
| [GSK504](GSK504.md) | Medium | Yes | Members can create public repositories |
| [GSK505](GSK505.md) | Medium | No | No security manager team assigned |
| [GSK506](GSK506.md) | High | Yes | Actions allows all third-party actions and reusable workflows |
| [GSK507](GSK507.md) | High | No | No default code security configuration for new repositories |
| [GSK508](GSK508.md) | Medium | No | Actions enabled for all repositories |
| [GSK509](GSK509.md) | High | Yes | Members can fork private repositories |
| [GSK510](GSK510.md) | High | Yes | Members can delete repositories |
| [GSK511](GSK511.md) | High | Yes | Members can change repository visibility |
| [GSK512](GSK512.md) | High | Yes | GITHUB_TOKEN default permissions are read-write |
| [GSK513](GSK513.md) | High | Yes | Actions can approve pull requests |
| [GSK514](GSK514.md) | High | Yes | Fork pull request workflows run without maintainer approval |
| [GSK515](GSK515.md) | Medium | Yes | Members can create private repositories |
| [GSK516](GSK516.md) | Medium | Yes | Members can create internal repositories |
| [GSK517](GSK517.md) | High | Yes | Actions SHA pinning not required |
| [GSK518](GSK518.md) | Medium | No | Immutable releases not enforced for all repositories |
| [GSK519](GSK519.md) | High | Yes | Private fork pull request workflows receive write tokens or secrets |
| [GSK520](GSK520.md) | Medium | No | Excessive organization owners |
| [GSK521](GSK521.md) | High | No | Suspended users remain organization owners |
| [GSK522](GSK522.md) | Medium | No | Suspended users remain organization members |
| [GSK523](GSK523.md) | High | Yes | Self-hosted runner group allows public repositories |
| [GSK524](GSK524.md) | High | No | Webhook uses insecure transport |
| [GSK525](GSK525.md) | Medium | No | Webhook has no secret |
