---
name: gh-secure-kit
description: gh-secure-kit is a GitHub CLI extension for security-related dependency management and workflow analysis. Use it to lint GitHub Actions workflows, analyze workflow dependencies, list SBOM packages, Git submodules, and Unity package manifests — all directly from the command line via `gh secure-kit`.
---

# gh-secure-kit

A GitHub CLI extension (`gh secure-kit`) to manage and inspect GitHub security-related dependencies and workflows.
It supports GitHub Actions workflow linting and dependency analysis, SBOM-based package listing, Git submodule listing, and Unity package inspection.

## Prerequisites

### Installation

```sh
gh extension install srz-zumix/gh-secure-kit
```

### Authentication

`gh secure-kit` uses the `gh` CLI's authentication. Ensure you are authenticated before using the extension:

```sh
gh auth login
gh auth status
```

## CLI Structure

```
gh secure-kit                      # Root command
├── actions                        # GitHub Actions security subcommands
│   ├── lint                       # Lint workflow/action YAML files
│   └── workflow                   # List action deps from workflow YAML
├── dependabot                     # Dependabot management subcommands
│   ├── alerts                     # Dependabot alerts subcommands
│   │   ├── get                    # Get a single Dependabot alert
│   │   ├── list                   # List Dependabot alerts
│   │   └── update                 # Update a Dependabot alert
│   └── repository-access          # Dependabot repository access subcommands
│       ├── list                   # List accessible repositories
│       ├── set-default-level      # Set default access level
│       └── update                 # Update repository access list
├── code-scanning                  # Code scanning subcommands
│   ├── alerts                     # Code scanning alerts subcommands
│   │   ├── get                    # Get a single code scanning alert
│   │   ├── list                   # List code scanning alerts
│   │   └── update                 # Update a code scanning alert
│   ├── analyses                   # Code scanning analyses subcommands
│   │   ├── get                    # Get a code scanning analysis
│   │   └── list                   # List code scanning analyses
│   ├── codeql                     # CodeQL database subcommands
│   │   ├── get                    # Get a CodeQL database by language
│   │   └── list                   # List CodeQL databases
│   └── sarif                      # SARIF upload subcommands
│       ├── get                    # Get SARIF upload info
│       └── upload                 # Upload SARIF data
└── deps                           # Dependency management subcommands
    ├── list                       # List dependency packages (SBOM)
    ├── actions                    # GitHub Actions dependency subcommands
    │   ├── graph                  # Graph Actions dependencies
    │   └── list                   # List Actions packages from SBOM
    ├── submodule                  # Git submodule subcommands
    │   └── list                   # List repository submodules
    └── unity                      # Unity project subcommands
        └── list                   # List Unity package dependencies
```

## Actions

### Lint workflow and action YAML files (gh secure-kit actions lint)

```sh
gh secure-kit actions lint [<workflow-id> | <workflow-name> | <filename>] [flags] [-- <tool-args>...]
```

Run an external lint tool (actionlint or zizmor) against workflow YAML and action.yml files fetched via the GitHub API.
Optionally specify a workflow by its ID, name, or filename to lint only that workflow's dependencies.
Extra arguments after `--` are passed directly to the lint tool.

```sh
# Lint all workflows in the current repository (default tool: zizmor)
gh secure-kit actions lint

# Use actionlint instead
gh secure-kit actions lint --tool actionlint

# Lint only a specific workflow
gh secure-kit actions lint ci.yml

# Recursively lint referenced action repositories
gh secure-kit actions lint --recursive

# Pass extra args to the lint tool
gh secure-kit actions lint -- --no-color

# Lint from a specific branch
gh secure-kit actions lint --ref main

# Keep downloaded files in a specific directory
gh secure-kit actions lint --tmpdir /tmp/lint-work
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--recursive` | `-r` | `false` | Recursively traverse referenced action repositories |
| `--ref` | | `""` | Git reference (branch, tag, or commit SHA) to read workflow files from |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--tmpdir` | | `""` | Directory to store downloaded files (default: auto-created temp dir, removed after lint) |
| `--tool` | | `"zizmor"` | Lint tool to use (supported: actionlint, zizmor) |

### List action dependencies from workflow YAML files (gh secure-kit actions workflow)

```sh
gh secure-kit actions workflow [<workflow-id> | <workflow-name> | <filename>] [flags]
```

Parse workflow YAML (`.github/workflows/*.yml`) and `action.yml` files to list GitHub Actions dependencies.
Unlike `gh secure-kit deps list`, this command parses YAML files directly without the Dependency Graph API.
`--min-node-version` and `--filter-using` automatically enable `--recursive` to populate `runs.using` fields.

```sh
# List all action dependencies in the current repository
gh secure-kit actions workflow

# List dependencies for a specific workflow
gh secure-kit actions workflow ci.yml

# Recursively traverse referenced action repositories
gh secure-kit actions workflow --recursive

# Show only action names
gh secure-kit actions workflow --name-only

# Show action names with version ref
gh secure-kit actions workflow --name-with-ref

# Filter: show only workflows/actions that use a Node action older than node24
gh secure-kit actions workflow --min-node-version 24

# Filter: show only actions using composite runtime
gh secure-kit actions workflow --filter-using composite

# Read from a specific branch/tag/SHA
gh secure-kit actions workflow --ref v1.2.3
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--field` | | | Comma-separated list of fields. Available: Name, Version, Owner, Repo, Path, Raw, Using, Node_Version, Job |
| `--filter-using` | | | Filter by `runs.using` type (e.g. `node16`, `composite`, `docker`); prefix match; repeatable; auto-enables `--recursive` |
| `--format` | | | Output format: {json\|dot\|drawio\|mermaid\|markdown\|tree} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--min-node-version` | | `0` | Filter to show only actions using a Node version older than specified (e.g. `24` → node20, node16); auto-enables `--recursive` |
| `--name-only` | | `false` | Output only action names |
| `--name-with-ref` | | `false` | Output action names with version ref (e.g. `actions/checkout@v4`) |
| `--recursive` | `-r` | `false` | Recursively traverse referenced action repositories |
| `--ref` | | `""` | Git reference (branch, tag, or commit SHA) to read workflow files from |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template |

## Deps

### List dependency packages (gh secure-kit deps list)

```sh
gh secure-kit deps list [flags]
```

List dependency packages in the repository's SBOM.

```sh
# List all packages in the current repository
gh secure-kit deps list

# List packages for a specific repository
gh secure-kit deps list --repo owner/repo

# Filter by ecosystem
gh secure-kit deps list --include npm
gh secure-kit deps list --include npm --include pip

# Exclude an ecosystem
gh secure-kit deps list --exclude rubygems

# Output package names only
gh secure-kit deps list --name-only

# JSON output
gh secure-kit deps list --format json
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--exclude` | `-e` | | Exclude packages by ecosystem (repeatable) |
| `--format` | | | Output format: {json} |
| `--include` | `-i` | | Filter by ecosystem (repeatable) |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--name-only` | | `false` | Output only package names |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template |

### Graph Actions dependencies (gh secure-kit deps actions graph)

```sh
gh secure-kit deps actions graph [flags]
```

Output dependency relationships of GitHub Actions as a graph. Use `--recursive` to traverse referenced action repositories.

```sh
# Output Mermaid flowchart (default)
gh secure-kit deps actions graph

# Output as DOT format
gh secure-kit deps actions graph --format dot

# Recursively include referenced action repositories
gh secure-kit deps actions graph --recursive
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | `"mermaid"` | Output format: {json\|dot\|drawio\|mermaid\|markdown} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--output` | `-o` | | Output file path (default: stdout) |
| `--recursive` | `-r` | `false` | Recursively traverse referenced action repositories |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template |

### List actions dependency packages (gh secure-kit deps actions list)

```sh
gh secure-kit deps actions list [flags]
```

List dependency packages related to GitHub Actions in the repository's SBOM. Use `--recursive` to traverse referenced action repositories.

```sh
# List Actions packages in the current repository
gh secure-kit deps actions list

# Recursively include referenced action repositories
gh secure-kit deps actions list --recursive

# JSON output
gh secure-kit deps actions list --format json
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--name-only` | | `false` | Output only package names |
| `--recursive` | `-r` | `false` | Recursively traverse referenced action repositories |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template |

### List repository submodules (gh secure-kit deps submodule list)

```sh
gh secure-kit deps submodule list [flags]
```

List submodules of the specified repository. Use `--recursive` to include nested submodules.

```sh
# List submodules in the current repository
gh secure-kit deps submodule list

# Recursively include nested submodules
gh secure-kit deps submodule list --recursive
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--name-only` | | `false` | Output only submodule names |
| `--recursive` | `-r` | `false` | Recursively list nested submodules |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template |

### List Unity package dependencies (gh secure-kit deps unity list)

```sh
gh secure-kit deps unity list [flags]
```

List dependency packages defined in a Unity project's Packages/manifest.json.

```sh
# List Unity packages in the current repository
gh secure-kit deps unity list

# Override manifest path
gh secure-kit deps unity list --path Packages/manifest.json

# Read from a specific branch
gh secure-kit deps unity list --ref main
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--field` | | `"Name,Version,SHA,Path,URL"` | Comma-separated list of fields to display in table output |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--name-only` | | `false` | Output only package names |
| `--path` | | `"Packages/manifest.json"` | Path to manifest.json within the repository |
| `--ref` | | `""` | Branch, tag, or commit SHA to read from |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template |

## Dependabot

### List Dependabot alerts (gh secure-kit dependabot alerts list)

```sh
gh secure-kit dependabot alerts list [flags]
```

List Dependabot alerts for a repository. Supports filtering by state, severity, ecosystem, and scope.

```sh
# List all Dependabot alerts in the current repository
gh secure-kit dependabot alerts list

# List alerts for a specific repository
gh secure-kit dependabot alerts list --repo owner/repo

# Filter by state
gh secure-kit dependabot alerts list --state open

# Filter by severity
gh secure-kit dependabot alerts list --severity critical

# Filter by ecosystem
gh secure-kit dependabot alerts list --ecosystem npm

# JSON output
gh secure-kit dependabot alerts list --format json
```

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
| `--template` | `-t` | | Format JSON output using a Go template |

### Get a Dependabot alert (gh secure-kit dependabot alerts get)

```sh
gh secure-kit dependabot alerts get <alert-number> [flags]
```

Get a single Dependabot alert by its number for a repository.

```sh
# Get alert #1 in the current repository
gh secure-kit dependabot alerts get 1

# Get alert for a specific repository
gh secure-kit dependabot alerts get 42 --repo owner/repo

# JSON output
gh secure-kit dependabot alerts get 1 --format json
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template |

### Update a Dependabot alert (gh secure-kit dependabot alerts update)

```sh
gh secure-kit dependabot alerts update <alert-number> --state <state> [flags]
```

Update a Dependabot alert for a repository. Use --state to change the alert state. A --dismissed-reason is required when setting state to dismissed.

```sh
# Reopen a dismissed alert
gh secure-kit dependabot alerts update 1 --state open

# Dismiss an alert with a reason
gh secure-kit dependabot alerts update 1 --state dismissed --dismissed-reason tolerable_risk

# Dismiss with a comment
gh secure-kit dependabot alerts update 1 --state dismissed --dismissed-reason not_used --dismissed-comment "Not applicable to our usage"
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--dismissed-comment` | | `""` | Optional comment associated with dismissing the alert |
| `--dismissed-reason` | | `""` | Reason for dismissing; required when state is dismissed {fix_started\|inaccurate\|no_bandwidth\|not_used\|tolerable_risk} |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--state` | | | The state to set {dismissed\|open} (required) |
| `--template` | `-t` | | Format JSON output using a Go template |

### List Dependabot accessible repositories (gh secure-kit dependabot repository-access list)

```sh
gh secure-kit dependabot repository-access list [flags]
```

Lists repositories that organization admins have allowed Dependabot to access when updating dependencies.

```sh
# List accessible repositories for the current repository's organization
gh secure-kit dependabot repository-access list

# List accessible repositories for a specific organization
gh secure-kit dependabot repository-access list --owner my-org

# JSON output
gh secure-kit dependabot repository-access list --owner my-org --format json
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name |
| `--template` | `-t` | | Format JSON output using a Go template |

### Set Dependabot default repository access level (gh secure-kit dependabot repository-access set-default-level)

```sh
gh secure-kit dependabot repository-access set-default-level --level <level> [flags]
```

Sets the default level of repository access Dependabot will have while performing an update. Available values are 'public' (only public repositories) and 'internal' (public and internal repositories).

```sh
# Set default level to public
gh secure-kit dependabot repository-access set-default-level --level public --owner my-org

# Set default level to internal
gh secure-kit dependabot repository-access set-default-level --level internal --owner my-org
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--level` | | | The default access level {public\|internal} (required) |
| `--owner` | `-o` | `""` | The organization name |

### Update Dependabot repository access list (gh secure-kit dependabot repository-access update)

```sh
gh secure-kit dependabot repository-access update [flags]
```

Updates repositories according to the list of repositories that organization admins have given Dependabot access to when they've updated dependencies. Use --add to add repository IDs and --remove to remove repository IDs.

```sh
# Add repositories by ID
gh secure-kit dependabot repository-access update --owner my-org --add 123 --add 456

# Remove repositories by ID
gh secure-kit dependabot repository-access update --owner my-org --remove 789

# Add and remove in one operation
gh secure-kit dependabot repository-access update --owner my-org --add 123 --remove 789
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--add` | | | Repository IDs to add (can be specified multiple times) |
| `--owner` | `-o` | `""` | The organization name |
| `--remove` | | | Repository IDs to remove (can be specified multiple times) |

## Code Scanning

### List code scanning alerts (gh secure-kit code-scanning alerts list)

```sh
gh secure-kit code-scanning alerts list [flags]
```

List code scanning alerts for a repository. Supports filtering by state, severity, tool, and ref.

```sh
# List all code scanning alerts in the current repository
gh secure-kit code-scanning alerts list

# Filter by state
gh secure-kit code-scanning alerts list --state open

# Filter by severity
gh secure-kit code-scanning alerts list --severity high

# Filter by tool name
gh secure-kit code-scanning alerts list --tool-name CodeQL

# Filter by ref
gh secure-kit code-scanning alerts list --ref main

# Sort by updated date, descending
gh secure-kit code-scanning alerts list --sort updated --direction desc

# List for a specific repository
gh secure-kit code-scanning alerts list --repo owner/repo
```

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

### Get a code scanning alert (gh secure-kit code-scanning alerts get)

```sh
gh secure-kit code-scanning alerts get <alert-number> [flags]
```

Get a single code scanning alert by its number for a repository.

```sh
# Get alert #42 in the current repository
gh secure-kit code-scanning alerts get 42

# Get alert in a specific repository
gh secure-kit code-scanning alerts get 42 --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Update a code scanning alert (gh secure-kit code-scanning alerts update)

```sh
gh secure-kit code-scanning alerts update <alert-number> --state <state> [flags]
```

Update a code scanning alert for a repository. Use --state to change the alert state. A --dismissed-reason is required when setting state to dismissed.

```sh
# Dismiss alert #42 with reason
gh secure-kit code-scanning alerts update 42 --state dismissed --dismissed-reason "false positive"

# Re-open alert #42
gh secure-kit code-scanning alerts update 42 --state open

# Dismiss with comment
gh secure-kit code-scanning alerts update 42 --state dismissed --dismissed-reason "won't fix" --dismissed-comment "Not exploitable in our context"
```

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

### List code scanning analyses (gh secure-kit code-scanning analyses list)

```sh
gh secure-kit code-scanning analyses list [flags]
```

Lists the details of all code scanning analyses for a repository, starting with the most recent.

```sh
# List all analyses in the current repository
gh secure-kit code-scanning analyses list

# Filter by ref
gh secure-kit code-scanning analyses list --ref main

# Filter by SARIF upload ID
gh secure-kit code-scanning analyses list --sarif-id 47177e22-5596-11eb-80a1-c1e54ef945c6

# List for a specific repository
gh secure-kit code-scanning analyses list --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--ref` | | `""` | Filter by Git ref (branch or tag) |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--sarif-id` | | `""` | Filter analyses belonging to the same SARIF upload |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get a code scanning analysis (gh secure-kit code-scanning analyses get)

```sh
gh secure-kit code-scanning analyses get <analysis-id> [flags]
```

Gets a specified code scanning analysis for a repository.

```sh
# Get analysis #201
gh secure-kit code-scanning analyses get 201

# Get analysis in a specific repository
gh secure-kit code-scanning analyses get 201 --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### List CodeQL databases (gh secure-kit code-scanning codeql list)

```sh
gh secure-kit code-scanning codeql list [flags]
```

Lists the CodeQL databases that are available in a repository.

```sh
# List CodeQL databases in the current repository
gh secure-kit code-scanning codeql list

# List for a specific repository
gh secure-kit code-scanning codeql list --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get a CodeQL database (gh secure-kit code-scanning codeql get)

```sh
gh secure-kit code-scanning codeql get <language> [flags]
```

Gets a CodeQL database for a language in a repository.

```sh
# Get the Java CodeQL database
gh secure-kit code-scanning codeql get java

# Get from a specific repository
gh secure-kit code-scanning codeql get python --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get information about a SARIF upload (gh secure-kit code-scanning sarif get)

```sh
gh secure-kit code-scanning sarif get <sarif-id> [flags]
```

Gets information about a SARIF upload, including the processing status and the URL of the analysis.

```sh
# Get SARIF upload status
gh secure-kit code-scanning sarif get 47177e22-5596-11eb-80a1-c1e54ef945c6

# Get for a specific repository
gh secure-kit code-scanning sarif get 47177e22-5596-11eb-80a1-c1e54ef945c6 --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Upload SARIF data (gh secure-kit code-scanning sarif upload)

```sh
gh secure-kit code-scanning sarif upload --commit-sha <sha> --ref <ref> --sarif <data> [flags]
```

Uploads SARIF data containing the results of a code scanning analysis. The --sarif value must be a base64-encoded SARIF payload, and GitHub typically expects gzip-compressed SARIF content encoded as base64 rather than raw JSON.

```sh
# Upload SARIF data
gh secure-kit code-scanning sarif upload \
  --commit-sha 4b6472266afd7b471e86085a6659e8c7f2b119da \
  --ref refs/heads/main \
  --sarif "H4sICMLGdF4AA2V4YW1wbGUu..."

# Upload with tool name and start time
gh secure-kit code-scanning sarif upload \
  --commit-sha abc123 \
  --ref refs/heads/main \
  --sarif "H4sICMLGdF4AA2V4YW1wbGUu..." \
  --tool-name "my-scanner" \
  --started-at "2024-01-01T00:00:00Z"
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--checkout-uri` | | `""` | The base directory used in the analysis |
| `--commit-sha` | | | The SHA of the commit to which the analysis relates (required) |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--ref` | | | The full Git reference (e.g. refs/heads/main) (required) |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--sarif` | | | Base64-encoded SARIF payload; typically gzip-compressed before encoding (required) |
| `--started-at` | | `""` | The time the analysis started (ISO 8601 format) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |
| `--tool-name` | | `""` | The name of the tool used to generate the analysis |
