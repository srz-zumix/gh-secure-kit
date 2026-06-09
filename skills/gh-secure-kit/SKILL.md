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
├── code-quality                   # Code quality subcommands
│   └── setup                      # Code quality setup subcommands
│       ├── get                    # Get code quality setup configuration
│       └── update                 # Update code quality setup configuration
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
    ├── diff                       # Show dependency diff between two commits or branches
    ├── list                       # List dependency packages (SBOM)
    ├── snapshot                   # Create a dependency graph snapshot
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

### Create dependency snapshot (gh secure-kit deps snapshot)

```sh
gh secure-kit deps snapshot --file <file> [flags]
```

Create a new dependency graph snapshot for a repository using the GitHub dependency submission API.
The snapshot body must be provided as a JSON file via `--file`.

**Key flags:** `--file` (required), `--repo`, `--format`

**Examples:**

```sh
gh secure-kit deps snapshot --file snapshot.json
gh secure-kit deps snapshot --repo owner/repo --file snapshot.json
gh secure-kit deps snapshot --file snapshot.json --format json
```

### Diff dependency changes (gh secure-kit deps diff)

```sh
gh secure-kit deps diff <basehead> [flags]
```

Show dependency changes between two commits, tags, or branches.
The `basehead` argument must be in the format `<base>...<head>`.

**Key flags:** `--repo`, `--format`

**Examples:**

```sh
gh secure-kit deps diff main...feature/branch
gh secure-kit deps diff v1.0.0...v2.0.0
gh secure-kit deps diff main...HEAD --format json
```

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

## Code Quality

### Get code quality setup configuration (gh secure-kit code-quality setup get)

```sh
gh secure-kit code-quality setup get [flags]
```

Gets the code quality setup configuration for a repository.

**Examples:**

```sh
gh secure-kit code-quality setup get
gh secure-kit code-quality setup get --repo owner/repo
gh secure-kit code-quality setup get --json state,languages
```

**Key Flags:**

| Flag | Description |
|------|-------------|
| `--repo` / `-R` | The repository in the format `owner/repo` |
| `--json` | Output JSON (specify fields) |

### Update code quality setup configuration (gh secure-kit code-quality setup update)

```sh
gh secure-kit code-quality setup update [flags]
```

Updates the code quality setup configuration for a repository. Supported languages: `csharp`, `go`, `java-kotlin`, `javascript-typescript`, `python`, `ruby`.

**Examples:**

```sh
gh secure-kit code-quality setup update --state configured --language javascript-typescript --language python
gh secure-kit code-quality setup update --state not-configured
gh secure-kit code-quality setup update --runner-type labeled --runner-label my-runner
```

**Key Flags:**

| Flag | Description |
|------|-------------|
| `--repo` / `-R` | The repository in the format `owner/repo` |
| `--state` | The desired state: `configured` or `not-configured` |
| `--language` | Language to analyze (can be specified multiple times) |
| `--runner-type` | Runner type: `standard` or `labeled` |
| `--runner-label` | Runner label (required when `--runner-type` is `labeled`) |

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

Uploads SARIF data containing the results of a code scanning analysis. The --sarif value must be a base64-encoded gzip-compressed SARIF payload rather than raw JSON.

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
| `--sarif` | | | Base64-encoded gzip-compressed SARIF payload (required) |
| `--started-at` | | `""` | The time the analysis started (ISO 8601 format) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |
| `--tool-name` | | `""` | The name of the tool used to generate the analysis |

## Code Security

### List code security configurations (gh secure-kit code-security configurations list)

```sh
gh secure-kit code-security configurations list [flags]
```

Lists all code security configurations available in an organization.

```sh
# List all configurations for an organization
gh secure-kit code-security configurations list --owner my-org

# Show only the global GitHub-recommended configurations
gh secure-kit code-security configurations list --owner my-org --target-type global

# Output JSON
gh secure-kit code-security configurations list --owner my-org --format json
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name |
| `--target-type` | | `""` | Filter by target type {all\|global} |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get a code security configuration (gh secure-kit code-security configurations get)

```sh
gh secure-kit code-security configurations get <configuration-id> [flags]
```

Gets a code security configuration in an organization by ID.

```sh
gh secure-kit code-security configurations get 1325 --owner my-org
```

**Flags**

| Flag | Shorthand | Default | Description |
| ---- | --------- | ------- | ----------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | `""` | The organization name |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |
### Create a code security configuration (gh secure-kit code-security configurations create)

```sh
gh secure-kit code-security configurations create --name <name> --description <desc> [feature flags] [flags]
```

Creates a code security configuration in an organization. `--name` and `--description` are required. Use feature flags to configure individual features. Most feature flags accept `enabled`, `disabled`, or `not_set`, while `--advanced-security` also accepts `code_security` and `secret_protection`.

```sh
# Minimal create
gh secure-kit code-security configurations create \
  --owner my-org \
  --name "octo-org recommended" \
  --description "Recommended settings"

# Create with several features enabled
gh secure-kit code-security configurations create \
  --owner my-org \
  --name "high risk" \
  --description "Stricter settings" \
  --advanced-security enabled \
  --dependabot-alerts enabled \
  --secret-scanning enabled \
  --secret-scanning-push-protection enabled \
  --enforcement enforced
```

See README for the full list of feature flags. The same set is accepted by `update`.

### Update a code security configuration (gh secure-kit code-security configurations update)

```sh
gh secure-kit code-security configurations update <configuration-id> [feature flags] [flags]
```

Updates a code security configuration. Only specified fields are sent.

```sh
gh secure-kit code-security configurations update 1325 \
  --owner my-org \
  --secret-scanning disabled \
  --code-scanning-default-setup enabled
```

### Delete a code security configuration (gh secure-kit code-security configurations delete)

```sh
gh secure-kit code-security configurations delete <configuration-id> [flags]
```

Deletes a code security configuration. Repositories attached to the configuration retain their settings but are no longer associated with it.

```sh
gh secure-kit code-security configurations delete 1325 --owner my-org
```

### Attach a configuration to repositories (gh secure-kit code-security configurations attach)

```sh
gh secure-kit code-security configurations attach <configuration-id> --scope <scope> [--repo-id <id>...] [flags]
```

Attaches a code security configuration to a set of repositories. `--scope=selected` requires one or more `--repo-id` values.

```sh
# Attach to all repositories without an existing configuration
gh secure-kit code-security configurations attach 1325 \
  --owner my-org --scope all_without_configurations

# Attach to specific repositories
gh secure-kit code-security configurations attach 1325 \
  --owner my-org --scope selected --repo-id 32 --repo-id 91
```

### Detach configurations from repositories (gh secure-kit code-security configurations detach)

```sh
gh secure-kit code-security configurations detach --repo-id <id>... [flags]
```

Detaches code security configurations from a set of repositories.

```sh
gh secure-kit code-security configurations detach \
  --owner my-org --repo-id 32 --repo-id 91
```

### List default code security configurations (gh secure-kit code-security configurations defaults)

```sh
gh secure-kit code-security configurations defaults [flags]
```

Lists the default code security configurations applied to new repositories in an organization.

```sh
gh secure-kit code-security configurations defaults --owner my-org
```

### Set a code security configuration as default (gh secure-kit code-security configurations set-default)

```sh
gh secure-kit code-security configurations set-default <configuration-id> --default-for-new-repos <scope> [flags]
```

Sets a code security configuration as a default to be applied to new repositories.

```sh
gh secure-kit code-security configurations set-default 1325 \
  --owner my-org --default-for-new-repos all
```

### List repositories attached to a configuration (gh secure-kit code-security configurations repositories)

```sh
gh secure-kit code-security configurations repositories <configuration-id> [flags]
```

Lists the repositories associated with a code security configuration.

```sh
gh secure-kit code-security configurations repositories 1325 --owner my-org

# Filter by attachment status
gh secure-kit code-security configurations repositories 1325 \
  --owner my-org --status attached
```

### Get the configuration attached to a repository (gh secure-kit code-security configurations repo-config)

```sh
gh secure-kit code-security configurations repo-config [flags]
```

Gets the code security configuration that manages a repository's code security settings.

```sh
gh secure-kit code-security configurations repo-config --repo owner/repo
```

## Security Advisories

### Create temporary private fork (gh secure-kit security-advisories create-fork)

```sh
gh secure-kit security-advisories create-fork <ghsa-id> [--repo <owner/repo>]
```

Create a temporary private fork of the repository to collaborate on fixing a security vulnerability.

### Get security advisory (gh secure-kit security-advisories get)

```sh
gh secure-kit security-advisories get <ghsa-id> [--repo <owner/repo>]
```

Get a repository security advisory by its GHSA identifier.

### List security advisories (gh secure-kit security-advisories list)

```sh
gh secure-kit security-advisories list [--repo <owner/repo>] [--owner <org>] [--state <state>] [--sort <field>] [--direction <asc|desc>]
```

List repository security advisories for a repository or organization. Use `--owner` for org-wide listing.

### Request CVE for security advisory (gh secure-kit security-advisories request-cve)

```sh
gh secure-kit security-advisories request-cve <ghsa-id> [--repo <owner/repo>]
```

Request a CVE identifier for a repository security advisory.

### Update security advisory (gh secure-kit security-advisories update)

```sh
gh secure-kit security-advisories update <ghsa-id> [--repo <owner/repo>] [--state <state>] [--severity <severity>]
```

Update a repository security advisory by its GHSA identifier. Supports updating state (published, closed, draft) and severity (critical, high, medium, low).

## Secret Scanning

### List secret scanning alerts (gh secure-kit secret-scanning alerts list)

```sh
gh secure-kit secret-scanning alerts list [flags]
```

List secret scanning alerts for a repository (use `--repo`) or for all repositories in an organization (use `--owner`). Supports filtering by state, secret type, resolution, and validity.

```sh
# List alerts for a repository
gh secure-kit secret-scanning alerts list --repo owner/repo

# List open alerts for an organization
gh secure-kit secret-scanning alerts list --owner my-org --state open

# Filter by validity and output as JSON
gh secure-kit secret-scanning alerts list --repo owner/repo --validity active --format json
```

### Get a secret scanning alert (gh secure-kit secret-scanning alerts get)

```sh
gh secure-kit secret-scanning alerts get <alert-number> [flags]
```

Get a single secret scanning alert by its number for a repository.

```sh
gh secure-kit secret-scanning alerts get 42 --repo owner/repo

# Output as JSON
gh secure-kit secret-scanning alerts get 42 --repo owner/repo --format json
```

### List locations for a secret scanning alert (gh secure-kit secret-scanning alerts locations)

```sh
gh secure-kit secret-scanning alerts locations <alert-number> [flags]
```

List all locations where a secret scanning alert was detected in the repository.

```sh
gh secure-kit secret-scanning alerts locations 42 --repo owner/repo
```

### Update a secret scanning alert (gh secure-kit secret-scanning alerts update)

```sh
gh secure-kit secret-scanning alerts update <alert-number> [flags]
```

Update the state of a secret scanning alert. A `--resolution` is required when setting state to `resolved`.

```sh
# Resolve an alert
gh secure-kit secret-scanning alerts update 42 \
  --repo owner/repo \
  --state resolved \
  --resolution false_positive \
  --resolution-comment "This is a test secret"

# Reopen an alert
gh secure-kit secret-scanning alerts update 42 --repo owner/repo --state open
```

### List secret scanning push protection pattern configurations (gh secure-kit secret-scanning push-protection list)

```sh
gh secure-kit secret-scanning push-protection list [flags]
```

List secret scanning push protection pattern configurations for an organization, including provider and custom pattern overrides.

```sh
gh secure-kit secret-scanning push-protection list --owner my-org

# Output as JSON
gh secure-kit secret-scanning push-protection list --owner my-org --format json
```

### Update secret scanning push protection pattern configurations (gh secure-kit secret-scanning push-protection update)

```sh
gh secure-kit secret-scanning push-protection update [flags]
```

Update secret scanning push protection pattern configurations for an organization. Use `--provider-pattern` in `TOKEN_TYPE=SETTING` format and `--custom-pattern` in `TOKEN_TYPE=SETTING` or `TOKEN_TYPE:VERSION=SETTING` format. Valid settings: `enabled`, `disabled`, `not_set`. The pattern config version must be obtained from the list command and passed via `--pattern-config-version`.

```sh
# Update a provider pattern
gh secure-kit secret-scanning push-protection update \
  --owner my-org \
  --pattern-config-version v1 \
  --provider-pattern "github_token=enabled"

# Update multiple patterns
gh secure-kit secret-scanning push-protection update \
  --owner my-org \
  --pattern-config-version v1 \
  --provider-pattern "github_token=enabled" \
  --custom-pattern "my_pattern=disabled" \
  --custom-pattern "other_pattern:2=not_set"
```

### Get secret scanning scan history for a repository (gh secure-kit secret-scanning scan-history)

```sh
gh secure-kit secret-scanning scan-history [flags]
```

Get the latest default incremental and backfill secret scanning scan history for a repository.

```sh
gh secure-kit secret-scanning scan-history --repo owner/repo

# Output as JSON
gh secure-kit secret-scanning scan-history --repo owner/repo --format json
```
