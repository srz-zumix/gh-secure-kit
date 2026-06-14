# gh-secure-kit

A tool to manage GitHub security-related dependencies and workflows.

## Installation

To install the tool, you can use the following command:

```sh
gh extension install srz-zumix/gh-secure-kit
```

## Shell Completion

**Workaround Available!** While gh CLI doesn't natively support extension completion, we provide a patch script that enables it.

**Prerequisites:** Before setting up gh-secure-kit completion, ensure gh CLI completion is configured for your shell. See [gh completion documentation](https://cli.github.com/manual/gh_completion) for setup instructions.

For detailed installation instructions and setup for each shell, see the [Shell Completion Guide](https://github.com/srz-zumix/go-gh-extension/blob/main/docs/shell-completion.md).

## Agent Skills

gh-secure-kit bundles agent skills for AI. Use the `skills` subcommand to install and manage them.

```sh
gh secure-kit skills [subcommand] [args...]
```

For details, see [Songmu/skillsmith](https://github.com/Songmu/skillsmith).

## Commands

## Actions

### Lint workflow and action YAML files

```sh
gh secure-kit actions lint [<workflow-id> | <workflow-name> | <filename>] [flags] [-- <tool-args>...]
```

Run an external lint tool against workflow YAML and action.yml files.
Files are fetched via the GitHub API and saved to a temporary directory,
then the specified lint tool is executed against them.
Optionally specify a workflow by its ID, name, or filename to lint only that workflow's dependencies.
Use --recursive to also lint files from referenced action repositories and reusable workflows.
Extra arguments after '--' are passed directly to the lint tool.

Supported tools: actionlint, zizmor

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--recursive` | `-r` | `false` | Recursively traverse referenced action repositories |
| `--ref` | | `""` | Git reference (branch, tag, or commit SHA) to read workflow files from |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--tmpdir` | | `""` | Directory to store downloaded files (default: auto-created temp dir, removed after lint) |
| `--tool` | | `"zizmor"` | Lint tool to use (supported: actionlint, zizmor) |

### List action dependencies from workflow YAML files

```sh
gh secure-kit actions workflow [<workflow-id> | <workflow-name> | <filename>] [flags]
```

Parse workflow YAML (.github/workflows/*.yml) and action.yml files in the repository to list GitHub Actions dependencies.
Unlike the `list` command which uses the Dependency Graph API, this command directly parses YAML files.
Optionally specify a workflow by its ID, name, or filename to parse only that workflow.
Use `--min-node-version` to filter for workflows and actions that depend on Node actions older than the specified version (automatically enables `--recursive`).
Use `--filter-using` to filter by `runs.using` type; prefix match is supported (automatically enables `--recursive`).

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--field` | | | Comma-separated list of fields to display in table output. Available fields: Name, Version, Owner, Repo, Path, Raw, Using, Node_Version, Job |
| `--filter-using` | | | Filter to show only actions/workflows whose `runs.using` matches the specified type (e.g. `node16`, `composite`, `docker`); prefix match supported (e.g. `node` matches `node16`/`node20`); repeatable; automatically enables `--recursive` |
| `--format` | | | Output format: {json\|dot\|drawio\|mermaid\|markdown\|tree} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--min-node-version` | | `0` | Filter to show only actions/workflows that use a Node action older than the specified version (e.g. `24` shows node20, node16); automatically enables `--recursive` |
| `--name-only` | | `false` | Output only action names |
| `--name-with-ref` | | `false` | Output action names with version ref (e.g. `actions/checkout@v4`) |
| `--recursive` | `-r` | `false` | Recursively traverse referenced action repositories |
| `--ref` | | `""` | Git reference (branch, tag, or commit SHA) to read workflow files from |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

## Deps

### Create dependency snapshot

```sh
gh secure-kit deps snapshot --file <file> [flags]
```

Create a new dependency graph snapshot for a repository. The snapshot body must be provided as a JSON file via `--file`.
The JSON must conform to the [GitHub dependency submission API schema](https://docs.github.com/rest/dependency-graph/dependency-submission).

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--file` | `-f` | | Path to a JSON file containing the snapshot body (required) |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Diff dependency changes

```sh
gh secure-kit deps diff <basehead> [flags]
```

Show dependency changes between two commits, tags, or branches using the GitHub dependency-graph compare API.
The `basehead` argument must be in the format `<base>...<head>` (e.g. `main...feature/branch`).

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List dependency packages

```sh
gh secure-kit deps list [flags]
```

List dependency packages in the repository's SBOM.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--exclude` | `-e` | | Exclude packages by ecosystem (can be specified multiple times) |
| `--format` | | | Output format: {json} |
| `--include` | `-i` | | Filter by ecosystem (can be specified multiple times) |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--name-only` | | `false` | Output only package names |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Graph actions dependency

```sh
gh secure-kit deps actions graph [flags]
```

Output dependency relationships of GitHub Actions as a Mermaid flowchart. Use --recursive to traverse referenced action repositories.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | `"mermaid"` | Output format: {json\|dot\|drawio\|mermaid\|markdown} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--output` | `-o` | | Output file path (default: stdout) |
| `--recursive` | `-r` | `false` | Recursively traverse referenced action repositories |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List actions dependency packages

```sh
gh secure-kit deps actions list [flags]
```

List dependency packages related to GitHub Actions in the repository's SBOM. Use --recursive to traverse referenced action repositories.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--name-only` | | `false` | Output only package names |
| `--recursive` | `-r` | `false` | Recursively traverse referenced action repositories |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List repository submodules

```sh
gh secure-kit deps submodule list [flags]
```

List submodules of the specified repository. Use --recursive to include nested submodules.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--name-only` | | `false` | Output only submodule names |
| `--recursive` | `-r` | `false` | Recursively list nested submodules |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List Unity package dependencies

```sh
gh secure-kit deps unity list [flags]
```

List dependency packages defined in a Unity project's Packages/manifest.json. The file path within the repository defaults to `Packages/manifest.json` and can be overridden with `--path`. Use `--ref` to target a specific branch, tag, or commit.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--field` | | `"Name,Version,SHA,Path,URL"` | Comma-separated list of fields to display in table output. Available fields: Name, Version, SHA, Path, URL |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--name-only` | | `false` | Output only package names |
| `--path` | | `"Packages/manifest.json"` | Path to manifest.json within the repository |
| `--ref` | | `""` | Branch, tag, or commit SHA to read from (default: repository default branch) |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

## Dependabot

### List Dependabot alerts

```sh
gh secure-kit dependabot alerts list [flags]
```

List Dependabot alerts for a repository or organization. Use `--repo` to list alerts for a specific repository, or `--owner` to list alerts across all repositories in an organization. `--repo` and `--owner` are mutually exclusive.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--direction` | | `""` | Sort direction {asc\|desc} |
| `--ecosystem` | | `""` | Filter by ecosystem {composer\|go\|maven\|npm\|nuget\|pip\|pub\|rubygems\|rust} |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name (lists alerts for all repositories in the org) |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--scope` | | `""` | Filter by scope {development\|runtime} |
| `--severity` | | `""` | Filter by severity {low\|medium\|high\|critical} |
| `--sort` | | `""` | Sort by field {created\|updated\|epss_percentage} |
| `--state` | | `""` | Filter by state {auto_dismissed\|dismissed\|fixed\|open} |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get a Dependabot alert

```sh
gh secure-kit dependabot alerts get <alert-number> [flags]
```

Get a single Dependabot alert by its number for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Update a Dependabot alert

```sh
gh secure-kit dependabot alerts update <alert-number> --state <state> [flags]
```

Update a Dependabot alert for a repository. Use --state to change the alert state. A --dismissed-reason is required when setting state to dismissed.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--dismissed-comment` | | `""` | Optional comment associated with dismissing the alert |
| `--dismissed-reason` | | `""` | Reason for dismissing; required when state is dismissed {fix_started\|inaccurate\|no_bandwidth\|not_used\|tolerable_risk} |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--state` | | | The state to set {dismissed\|open} (required) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List Dependabot accessible repositories

```sh
gh secure-kit dependabot repository-access list [flags]
```

Lists repositories that organization admins have allowed Dependabot to access when updating dependencies.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Set Dependabot default repository access level

```sh
gh secure-kit dependabot repository-access set-default-level --level <level> [flags]
```

Sets the default level of repository access Dependabot will have while performing an update. Available values are 'public' (only public repositories) and 'internal' (public and internal repositories).

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--level` | | | The default access level {public\|internal} (required) |
| `--owner` | `-o` | `""` | The organization name |

### Update Dependabot repository access list

```sh
gh secure-kit dependabot repository-access update [flags]
```

Updates repositories according to the list of repositories that organization admins have given Dependabot access to when they've updated dependencies. Use --add to add repository IDs and --remove to remove repository IDs.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--add` | | | Repository IDs to add (can be specified multiple times) |
| `--owner` | `-o` | `""` | The organization name |
| `--remove` | | | Repository IDs to remove (can be specified multiple times) |

## Code Quality

### Get code quality setup configuration

```sh
gh secure-kit code-quality setup get [flags]
```

Gets the code quality setup configuration for a repository. Returns the current state, configured languages, runner type, and schedule.

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--repo` | `-R` | | The repository in the format `owner/repo` |
| `--json` | | | Output JSON (specify fields) |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--template` | `-t` | | Format JSON output using a Go template |

### Update code quality setup configuration

```sh
gh secure-kit code-quality setup update [flags]
```

Updates the code quality setup configuration for a repository. Use `--state` to enable or disable code quality analysis, `--language` to specify languages (can be repeated), and `--runner-type` to set the runner type.

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--repo` | `-R` | | The repository in the format `owner/repo` |
| `--state` | | | The desired state: `configured` or `not-configured` |
| `--language` | | | Language to analyze (can be specified multiple times). Supported: `csharp`, `go`, `java-kotlin`, `javascript-typescript`, `python`, `ruby` |
| `--runner-type` | | | Runner type to use: `standard` or `labeled` |
| `--runner-label` | | | Runner label to use when `--runner-type` is `labeled` |

## Code Scanning

### List code scanning alerts

```sh
gh secure-kit code-scanning alerts list [flags]
```

List code scanning alerts for a repository or organization. Use `--repo` to list alerts for a specific repository, or `--owner` to list alerts across all repositories in an organization. `--repo` and `--owner` are mutually exclusive.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--direction` | | `""` | Sort direction {asc\|desc} |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name (lists alerts for all repositories in the org) |
| `--ref` | | `""` | Filter by Git ref (branch, tag, or pull request) |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--severity` | | `""` | Filter by severity {critical\|error\|high\|low\|medium\|note\|warning} |
| `--sort` | | `""` | Sort by field {created\|updated} |
| `--state` | | `""` | Filter by state {closed\|dismissed\|fixed\|open} |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |
| `--tool-guid` | | `""` | Filter by tool GUID |
| `--tool-name` | | `""` | Filter by tool name |

### Get a code scanning alert

```sh
gh secure-kit code-scanning alerts get <alert-number> [flags]
```

Get a single code scanning alert by its number for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Update a code scanning alert

```sh
gh secure-kit code-scanning alerts update <alert-number> --state <state> [flags]
```

Update a code scanning alert for a repository. Use --state to change the alert state. A --dismissed-reason is required when setting state to dismissed.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--dismissed-comment` | | `""` | Optional comment associated with dismissing the alert |
| `--dismissed-reason` | | `""` | Reason for dismissing; required when state is dismissed {false positive\|used in tests\|won't fix} |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--state` | | | The state to set {dismissed\|open} (required) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get the autofix status for a code scanning alert

```sh
gh secure-kit code-scanning alerts autofix get <alert-number> [flags]
```

Get the status and description of an autofix for a code scanning alert on the repository's default branch.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Create an autofix for a code scanning alert

```sh
gh secure-kit code-scanning alerts autofix create <alert-number> [flags]
```

Create an autofix for a code scanning alert. Returns 200 OK if an autofix already exists, or 202 Accepted if a new one is being generated.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Commit an autofix for a code scanning alert

```sh
gh secure-kit code-scanning alerts autofix commit <alert-number> [--target-ref <ref>] [--message <msg>] [flags]
```

Commit an autofix for a code scanning alert from the repository's default branch. The target branch must already exist. If `--target-ref` is omitted, the default branch is used.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--message` | | `""` | Commit message for the autofix commit |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--target-ref` | | `""` | The Git reference of the target branch for the commit (e.g. refs/heads/my-fix) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List code scanning analyses

```sh
gh secure-kit code-scanning analyses list [flags]
```

Lists the details of all code scanning analyses for a repository, starting with the most recent.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--ref` | | `""` | Filter by Git ref (branch or tag) |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--sarif-id` | | `""` | Filter analyses belonging to the same SARIF upload |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get a code scanning analysis

```sh
gh secure-kit code-scanning analyses get <analysis-id> [flags]
```

Gets a specified code scanning analysis for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List CodeQL databases

```sh
gh secure-kit code-scanning codeql list [flags]
```

Lists the CodeQL databases that are available in a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get a CodeQL database

```sh
gh secure-kit code-scanning codeql get <language> [flags]
```

Gets a CodeQL database for a language in a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get information about a SARIF upload

```sh
gh secure-kit code-scanning sarif get <sarif-id> [flags]
```

Gets information about a SARIF upload, including the processing status and the URL of the analysis.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Upload SARIF data

```sh
gh secure-kit code-scanning sarif upload --commit-sha <sha> --ref <ref> --sarif <data> [flags]
```

Uploads SARIF data containing the results of a code scanning analysis. The --sarif value must be a base64-encoded gzip-compressed SARIF payload rather than raw JSON.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--checkout-uri` | | `""` | The base directory used in the analysis |
| `--commit-sha` | | | The SHA of the commit to which the analysis relates (required) |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--ref` | | | The full Git reference (e.g. refs/heads/main) (required) |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--sarif` | | | Base64-encoded gzip-compressed SARIF payload (required) |
| `--started-at` | | `""` | The time the analysis started (ISO 8601 format) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |
| `--tool-name` | | `""` | The name of the tool used to generate the analysis |

## Code Security

### List code security configurations

```sh
gh secure-kit code-security configurations list [flags]
```

Lists all code security configurations available in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name |
| `--target-type` | | `""` | Filter by target type {all\|global} |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get a code security configuration

```sh
gh secure-kit code-security configurations get <configuration-id> [flags]
```

Gets a code security configuration in an organization by ID.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Create a code security configuration

```sh
gh secure-kit code-security configurations create --name <name> --description <desc> [feature flags] [flags]
```

Creates a code security configuration in an organization. `--name` and `--description` are required. Use feature flags below to configure individual features.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--advanced-security` | | `""` | Enablement status of GitHub Advanced Security {code_security\|disabled\|enabled\|secret_protection} |
| `--code-scanning-default-setup` | | `""` | Enablement status of code scanning default setup {disabled\|enabled\|not_set} |
| `--code-scanning-delegated-alert-dismissal` | | `""` | Enablement status of code scanning delegated alert dismissal {disabled\|enabled\|not_set} |
| `--code-security` | | `""` | Enablement status of GitHub Code Security {disabled\|enabled\|not_set} |
| `--dependabot-alerts` | | `""` | Enablement status of Dependabot alerts {disabled\|enabled\|not_set} |
| `--dependabot-security-updates` | | `""` | Enablement status of Dependabot security updates {disabled\|enabled\|not_set} |
| `--dependency-graph` | | `""` | Enablement status of Dependency Graph {disabled\|enabled\|not_set} |
| `--dependency-graph-autosubmit-action` | | `""` | Enablement status of automatic dependency submission {disabled\|enabled\|not_set} |
| `--description` | | | A description of the code security configuration (required) |
| `--enforcement` | | `""` | Enforcement status {enforced\|unenforced} |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--name` | | | The name of the code security configuration (required) |
| `--owner` | `-o` | `""` | The organization name |
| `--private-vulnerability-reporting` | | `""` | Enablement status of private vulnerability reporting {disabled\|enabled\|not_set} |
| `--secret-protection` | | `""` | Enablement status of GitHub Secret Protection {disabled\|enabled\|not_set} |
| `--secret-scanning` | | `""` | Enablement status of secret scanning {disabled\|enabled\|not_set} |
| `--secret-scanning-delegated-alert-dismissal` | | `""` | Enablement status of secret scanning delegated alert dismissal {disabled\|enabled\|not_set} |
| `--secret-scanning-delegated-bypass` | | `""` | Enablement status of secret scanning delegated bypass {disabled\|enabled\|not_set} |
| `--secret-scanning-generic-secrets` | | `""` | Enablement status of Copilot secret scanning {disabled\|enabled\|not_set} |
| `--secret-scanning-non-provider-patterns` | | `""` | Enablement status of secret scanning non-provider patterns {disabled\|enabled\|not_set} |
| `--secret-scanning-push-protection` | | `""` | Enablement status of secret scanning push protection {disabled\|enabled\|not_set} |
| `--secret-scanning-validity-checks` | | `""` | Enablement status of secret scanning validity checks {disabled\|enabled\|not_set} |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Update a code security configuration

```sh
gh secure-kit code-security configurations update <configuration-id> [feature flags] [flags]
```

Updates a code security configuration in an organization. Only specified fields are sent. The same feature flags as `create` are accepted; only `--name` and `--description` are not required.

### Delete a code security configuration

```sh
gh secure-kit code-security configurations delete <configuration-id> [flags]
```

Deletes a code security configuration. Repositories attached to the configuration retain their settings but are no longer associated with it.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | `""` | The organization name |

### Attach a code security configuration to repositories

```sh
gh secure-kit code-security configurations attach <configuration-id> --scope <scope> [--repo-id <id>...] [flags]
```

Attaches a code security configuration to a set of repositories in an organization. `--scope=selected` requires one or more `--repo-id` values.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | `""` | The organization name |
| `--repo-id` | | `[]` | Repository IDs to attach (only with `--scope=selected`, repeatable) |
| `--scope` | | | Type of repositories to attach to {all\|all_without_configurations\|private_or_internal\|public\|selected} (required) |

### Detach code security configurations from repositories

```sh
gh secure-kit code-security configurations detach --repo-id <id>... [flags]
```

Detaches code security configurations from a set of repositories. Repositories retain their settings but are no longer associated with any configuration.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | `""` | The organization name |
| `--repo-id` | | `[]` | Repository IDs to detach (repeatable, up to 250) (required) |

### List default code security configurations

```sh
gh secure-kit code-security configurations defaults [flags]
```

Lists the default code security configurations applied to new repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Set a code security configuration as default

```sh
gh secure-kit code-security configurations set-default <configuration-id> --default-for-new-repos <scope> [flags]
```

Sets a code security configuration as a default to be applied to new repositories in the organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--default-for-new-repos` | | | Repository types this configuration applies to by default {all\|none\|private_and_internal\|public} (required) |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List repositories attached to a code security configuration

```sh
gh secure-kit code-security configurations repositories <configuration-id> [flags]
```

Lists the repositories associated with a code security configuration in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name |
| `--status` | | `""` | Filter by attachment status {all\|attached\|attaching\|detached\|enforced\|failed\|removed\|removed_by_enterprise\|updating} |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get the code security configuration attached to a repository

```sh
gh secure-kit code-security configurations repo-config [flags]
```

Gets the code security configuration that manages a repository's code security settings.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

## Security Advisories

### Create temporary private fork

```sh
gh secure-kit security-advisories create-fork <ghsa-id> [--repo <owner/repo>]
```

Create a temporary private fork of the repository to collaborate on fixing a security vulnerability. The `--repo` flag is optional and defaults to the current repository.

**Arguments:**

| Argument | Description |
| -------- | ----------- |
| `ghsa-id` | The GHSA identifier of the advisory (required) |

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |

### Get security advisory

```sh
gh secure-kit security-advisories get <ghsa-id> [--repo <owner/repo>]
```

Get a repository security advisory by its GHSA identifier. The `--repo` flag is optional and defaults to the current repository.

**Arguments:**

| Argument | Description |
| -------- | ----------- |
| `ghsa-id` | The GHSA identifier of the advisory (required) |

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List security advisories

```sh
gh secure-kit security-advisories list [--repo <owner/repo>] [--owner <org>] [--state <state>] [--sort <field>] [--direction <asc|desc>]
```

List repository security advisories for a repository or organization. Use `--repo` to list advisories for a specific repository, or `--owner` to list advisories across all repositories in an organization. `--repo` and `--owner` are mutually exclusive. If neither is specified, the current repository is used.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--direction` | | `""` | Sort direction: {asc\|desc} |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name (lists advisories for all repositories in the org) |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--sort` | | `""` | Sort by field: {created\|updated\|published} |
| `--state` | | `""` | Filter by state: {triage\|draft\|published\|closed} |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Request CVE for security advisory

```sh
gh secure-kit security-advisories request-cve <ghsa-id> [--repo <owner/repo>]
```

Request a CVE (Common Vulnerabilities and Exposures) identifier for a repository security advisory. The `--repo` flag is optional and defaults to the current repository.

**Arguments:**

| Argument | Description |
| -------- | ----------- |
| `ghsa-id` | The GHSA identifier of the advisory (required) |

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |

### Update security advisory

```sh
gh secure-kit security-advisories update <ghsa-id> [--repo <owner/repo>] [--state <state>] [--severity <severity>]
```

Update a repository security advisory by its GHSA identifier. Use `--state` to change the state (published, closed, draft) and `--severity` to change the severity. The `--repo` flag is optional and defaults to the current repository.

**Arguments:**

| Argument | Description |
| -------- | ----------- |
| `ghsa-id` | The GHSA identifier of the advisory (required) |

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--severity` | | `""` | The severity: {critical\|high\|medium\|low} |
| `--state` | | `""` | The new state: {published\|closed\|draft} |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

## Secret Scanning

### List secret scanning alerts

```sh
gh secure-kit secret-scanning alerts list [flags]
```

List secret scanning alerts for a repository or organization. Use `--repo` for repository-level alerts or `--owner` for all alerts across an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--direction` | | `""` | Sort direction {asc\|desc} |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name (lists alerts for all repositories in the org) |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--resolution` | | `""` | Filter by resolution {false_positive\|wont_fix\|revoked\|used_in_tests\|pattern_edited\|pattern_deleted} |
| `--secret-type` | | `""` | Filter by secret type (comma-separated) |
| `--sort` | | `""` | Sort by field {created\|updated} |
| `--state` | | `""` | Filter by state {open\|resolved} |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |
| `--validity` | | `""` | Filter by validity {active\|inactive\|unknown} |

### Get a secret scanning alert

```sh
gh secure-kit secret-scanning alerts get <alert-number> [flags]
```

Get a single secret scanning alert by its number for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List locations for a secret scanning alert

```sh
gh secure-kit secret-scanning alerts locations <alert-number> [flags]
```

List all locations where a secret scanning alert was detected in the repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Update a secret scanning alert

```sh
gh secure-kit secret-scanning alerts update <alert-number> [flags]
```

Update a secret scanning alert for a repository. Use `--state` to change the alert state. A `--resolution` is required when setting state to `resolved`.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--resolution` | | `""` | Reason for resolving; required when state is resolved {false_positive\|wont_fix\|revoked\|used_in_tests} |
| `--resolution-comment` | | `""` | Optional comment associated with resolving the alert |
| `--state` | | | The state to set {open\|resolved} (required) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List secret scanning push protection pattern configurations

```sh
gh secure-kit secret-scanning push-protection list [flags]
```

List secret scanning push protection pattern configurations for an organization, including provider and custom pattern overrides.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Update secret scanning push protection pattern configurations

```sh
gh secure-kit secret-scanning push-protection update [flags]
```

Update secret scanning push protection pattern configurations for an organization. Use `--provider-pattern` to update provider patterns in `TOKEN_TYPE=SETTING` format. Use `--custom-pattern` to update custom patterns in `TOKEN_TYPE=SETTING` or `TOKEN_TYPE:VERSION=SETTING` format. Valid settings: `enabled`, `disabled`, `not_set`. Obtain the pattern config version from the list command and pass it via `--pattern-config-version`.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--custom-pattern` | | | Custom pattern setting in TOKEN_TYPE=SETTING or TOKEN_TYPE:VERSION=SETTING format (repeatable) |
| `--owner` | `-o` | `""` | The organization name |
| `--pattern-config-version` | | `""` | The pattern config version (from list command) |
| `--provider-pattern` | | | Provider pattern setting in TOKEN_TYPE=SETTING format (repeatable) |

### Get secret scanning scan history for a repository

```sh
gh secure-kit secret-scanning scan-history [flags]
```

Get the latest default incremental and backfill secret scanning scan history for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

