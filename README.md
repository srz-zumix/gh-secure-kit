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

List Dependabot alerts for a repository. Supports filtering by state, severity, ecosystem, and scope.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--direction` | | `""` | Sort direction {asc\|desc} |
| `--ecosystem` | | `""` | Filter by ecosystem {composer\|go\|maven\|npm\|nuget\|pip\|pub\|rubygems\|rust} |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
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

## Code Scanning

### List code scanning alerts

```sh
gh secure-kit code-scanning alerts list [flags]
```

List code scanning alerts for a repository. Supports filtering by state, severity, tool, and ref.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--direction` | | `""` | Sort direction {asc\|desc} |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
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
