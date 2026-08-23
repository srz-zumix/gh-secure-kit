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
├── advanced-security              # GitHub Advanced Security subcommands
│   ├── disable                    # Disable GitHub Advanced Security for an org
│   └── enable                     # Enable GitHub Advanced Security for an org
├── dependabot                     # Dependabot management subcommands
│   ├── alerts                     # Dependabot alerts subcommands
│   │   ├── disable                # Disable Dependabot alerts for an org
│   │   ├── enable                 # Enable Dependabot alerts for an org
│   │   ├── get                    # Get a single Dependabot alert
│   │   ├── list                   # List Dependabot alerts
│   │   └── update                 # Update a Dependabot alert
│   ├── repository-access          # Dependabot repository access subcommands
│   │   ├── list                   # List accessible repositories
│   │   ├── set-default-level      # Set default access level
│   │   └── update                 # Update repository access list
│   └── security-updates           # Dependabot security updates subcommands
│       ├── disable                # Disable Dependabot security updates for an org
│       └── enable                 # Enable Dependabot security updates for an org
├── code-quality                   # Code quality subcommands
│   └── setup                      # Code quality setup subcommands
│       ├── get                    # Get code quality setup configuration
│       └── update                 # Update code quality setup configuration
├── code-scanning                  # Code scanning subcommands
│   ├── alerts                     # Code scanning alerts subcommands
│   │   ├── autofix                # Code scanning autofix subcommands
│   │   │   ├── commit             # Commit an autofix
│   │   │   ├── create             # Create an autofix
│   │   │   └── get                # Get autofix status
│   │   ├── get                    # Get a single code scanning alert
│   │   ├── instances              # List instances of a code scanning alert
│   │   ├── list                   # List code scanning alerts
│   │   └── update                 # Update a code scanning alert
│   ├── analyses                   # Code scanning analyses subcommands
│   │   ├── delete                 # Delete a code scanning analysis
│   │   ├── get                    # Get a code scanning analysis
│   │   └── list                   # List code scanning analyses
│   ├── codeql                     # CodeQL database subcommands
│   │   ├── delete                 # Delete a CodeQL database by language
│   │   ├── get                    # Get a CodeQL database by language
│   │   ├── list                   # List CodeQL databases
│   │   └── variant-analyses       # CodeQL variant analysis subcommands
│   │       ├── create             # Create a CodeQL variant analysis
│   │       ├── get                # Get the summary of a CodeQL variant analysis
│   │       └── repo-status        # Get a repository's analysis status in a variant analysis
│   ├── default-setup              # Code scanning default setup subcommands
│   │   ├── disable                # Disable code scanning default setup for an org
│   │   ├── enable                 # Enable code scanning default setup for an org
│   │   ├── get                    # Get a repository's default setup configuration
│   │   └── update                 # Update a repository's default setup configuration
│   └── sarif                      # SARIF upload subcommands
│       ├── get                    # Get SARIF upload info
│       └── upload                 # Upload SARIF data
├── code-security                  # Code security subcommands
│   └── configurations             # Code security configurations subcommands
│       ├── list                   # List configurations
│       ├── get                    # Get a configuration by ID
│       ├── create                 # Create a configuration
│       ├── update                 # Update a configuration
│       ├── delete                 # Delete a configuration
│       ├── attach                 # Attach a configuration to repositories
│       ├── detach                 # Detach configurations from repositories
│       ├── defaults               # List default configurations
│       ├── set-default            # Set a default configuration
│       ├── repositories           # List repositories attached to a configuration
│       └── repo-config            # Get repository's attached configuration
├── deps                           # Dependency management subcommands
│   ├── diff                       # Show dependency diff between two commits or branches
│   ├── disable                    # Disable dependency graph for an org
│   ├── enable                     # Enable dependency graph for an org
│   ├── list                       # List dependency packages (SBOM)
│   ├── snapshot                   # Create a dependency graph snapshot
│   ├── actions                    # GitHub Actions dependency subcommands
│   │   ├── graph                  # Graph Actions dependencies
│   │   └── list                   # List Actions packages from SBOM
│   ├── sbom                       # SBOM report subcommands
│   │   ├── generate-report        # Request generation of an SBOM report
│   │   └── fetch-report           # Fetch a previously generated SBOM report
│   ├── submodule                  # Git submodule subcommands
│   │   └── list                   # List repository submodules
│   └── unity                      # Unity project subcommands
│       └── list                   # List Unity package dependencies
├── secret-scanning                # Secret scanning subcommands
│   ├── disable                    # Disable secret scanning for an org
│   ├── enable                     # Enable secret scanning for an org
│   ├── alerts                     # Secret scanning alerts subcommands
│   │   ├── get                    # Get a single secret scanning alert
│   │   ├── list                   # List secret scanning alerts
│   │   ├── locations              # List locations for a secret scanning alert
│   │   └── update                 # Update a secret scanning alert
│   ├── local                      # Offline local secret scanning subcommands
│   │   ├── check                  # Scan local git content for secrets
│   │   ├── hook                   # Manage git hooks running local secret scanning
│   │   │   ├── install            # Install pre-push (default) or pre-commit hooks
│   │   │   ├── status             # Show hook installation state
│   │   │   └── uninstall          # Remove installed hooks
│   │   └── patterns               # List local secret scanning patterns
│   ├── push-protection            # Secret scanning push protection subcommands
│   │   ├── disable                # Disable push protection for an org
│   │   ├── enable                 # Enable push protection for an org
│   │   ├── list                   # List push protection configurations
│   │   └── update                 # Update push protection configurations
│   └── scan-history               # Get secret scanning scan history
└── security-advisories            # Repository security advisories subcommands
    ├── create                     # Create a repository security advisory
    ├── create-fork                # Create a temporary private fork for an advisory
    ├── get                        # Get a repository security advisory
    ├── global                     # Global security advisories subcommands
    │   ├── get                    # Get a global security advisory by GHSA ID
    │   └── list                   # List global security advisories
    ├── list                       # List repository security advisories
    ├── report                     # Report a vulnerability in a repository
    ├── request-cve                # Request a CVE for a security advisory
    └── update                     # Update a repository security advisory
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

### Request SBOM report generation (gh secure-kit deps sbom generate-report)

```sh
gh secure-kit deps sbom generate-report [flags]
```

Trigger a job to generate a software bill of materials (SBOM) report for a repository in SPDX JSON format.
Use `deps sbom fetch-report` to retrieve the result once ready.

```sh
# Request an SBOM report for the current repository
gh secure-kit deps sbom generate-report

# Request an SBOM report for a specific repository
gh secure-kit deps sbom generate-report --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template |

### Fetch SBOM report (gh secure-kit deps sbom fetch-report)

```sh
gh secure-kit deps sbom fetch-report <sbom-uuid> [flags]
```

Fetch a software bill of materials (SBOM) report previously requested via `deps sbom generate-report`.
If the report is not ready yet, a pending message is shown; retry later.

```sh
# Fetch a previously requested SBOM report
gh secure-kit deps sbom fetch-report 00000000-0000-0000-0000-000000000000
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
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

### Disable dependency graph for an organization (gh secure-kit deps disable)

```sh
gh secure-kit deps disable --owner <org>
```

Disable the dependency graph for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

### Enable dependency graph for an organization (gh secure-kit deps enable)

```sh
gh secure-kit deps enable --owner <org>
```

Enable the dependency graph for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

## Dependabot

### List Dependabot alerts (gh secure-kit dependabot alerts list)

```sh
gh secure-kit dependabot alerts list [flags]
```

List Dependabot alerts for a repository or organization. Use `--repo` to list alerts for a specific repository, or `--owner` to list alerts across all repositories in an organization. `--repo` and `--owner` are mutually exclusive.

```sh
# List all Dependabot alerts in the current repository
gh secure-kit dependabot alerts list

# List alerts for a specific repository
gh secure-kit dependabot alerts list --repo owner/repo

# List alerts across all repositories in an organization
gh secure-kit dependabot alerts list --owner my-org

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
| `--owner` | `-o` | `""` | The organization name (lists alerts for all repositories in the org) |
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

### Disable Dependabot alerts for an organization (gh secure-kit dependabot alerts disable)

```sh
gh secure-kit dependabot alerts disable --owner <org>
```

Disable Dependabot alerts for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

### Enable Dependabot alerts for an organization (gh secure-kit dependabot alerts enable)

```sh
gh secure-kit dependabot alerts enable --owner <org>
```

Enable Dependabot alerts for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

### Disable Dependabot security updates for an organization (gh secure-kit dependabot security-updates disable)

```sh
gh secure-kit dependabot security-updates disable --owner <org>
```

Disable Dependabot security updates for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

### Enable Dependabot security updates for an organization (gh secure-kit dependabot security-updates enable)

```sh
gh secure-kit dependabot security-updates enable --owner <org>
```

Enable Dependabot security updates for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

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

List code scanning alerts for a repository or organization. Use `--repo` to list alerts for a specific repository, or `--owner` to list alerts across all repositories in an organization. `--repo` and `--owner` are mutually exclusive.

```sh
# List all code scanning alerts in the current repository
gh secure-kit code-scanning alerts list

# List alerts across all repositories in an organization
gh secure-kit code-scanning alerts list --owner my-org

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
| `--owner` | `-o` | `""` | The organization name (lists alerts for all repositories in the org) |
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

### List instances of a code scanning alert (gh secure-kit code-scanning alerts instances)

```sh
gh secure-kit code-scanning alerts instances <alert-number> [flags]
```

Lists all instances of the specified code scanning alert for a repository.

```sh
# List all instances of alert #42
gh secure-kit code-scanning alerts instances 42

# Filter by ref
gh secure-kit code-scanning alerts instances 42 --ref refs/heads/main

# List for a specific repository
gh secure-kit code-scanning alerts instances 42 --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--ref` | | `""` | Filter by Git ref (branch, tag, or pull request) |
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

### Get the autofix status for a code scanning alert (gh secure-kit code-scanning alerts autofix get)

```sh
gh secure-kit code-scanning alerts autofix get <alert-number> [flags]
```

Get the status and description of an autofix for a code scanning alert on the repository's default branch.

```sh
gh secure-kit code-scanning alerts autofix get 42 --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Create an autofix for a code scanning alert (gh secure-kit code-scanning alerts autofix create)

```sh
gh secure-kit code-scanning alerts autofix create <alert-number> [flags]
```

Create an autofix for a code scanning alert. Returns 200 OK if an autofix already exists, or 202 Accepted if a new one is being generated.

```sh
gh secure-kit code-scanning alerts autofix create 42 --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Commit an autofix for a code scanning alert (gh secure-kit code-scanning alerts autofix commit)

```sh
gh secure-kit code-scanning alerts autofix commit <alert-number> [--target-ref <ref>] [--message <msg>] [flags]
```

Commit an autofix for a code scanning alert from the repository's default branch. The target branch must already exist. If `--target-ref` is omitted, the default branch is used.

```sh
# Commit to the default branch
gh secure-kit code-scanning alerts autofix commit 42 --repo owner/repo

# Commit to a specific branch with a custom message
gh secure-kit code-scanning alerts autofix commit 42 \
  --repo owner/repo \
  --target-ref refs/heads/fix/alert-42 \
  --message "fix: apply autofix for alert #42"
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--message` | | `""` | Commit message for the autofix commit |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--target-ref` | | `""` | The Git reference of the target branch for the commit (e.g. refs/heads/my-fix) |
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

### Delete a code scanning analysis (gh secure-kit code-scanning analyses delete)

```sh
gh secure-kit code-scanning analyses delete <analysis-id> [flags]
```

Deletes a specified code scanning analysis from a repository. You can delete one analysis at a time, starting with the most recent.

```sh
# Delete analysis #201
gh secure-kit code-scanning analyses delete 201

# Allow deleting the last analysis in a set
gh secure-kit code-scanning analyses delete 201 --confirm-delete
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--confirm-delete` | | `false` | Allow deletion if the specified analysis is the last in a set |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |

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

### Delete a CodeQL database (gh secure-kit code-scanning codeql delete)

```sh
gh secure-kit code-scanning codeql delete <language> [flags]
```

Deletes a CodeQL database for a language in a repository.

```sh
# Delete the Java CodeQL database
gh secure-kit code-scanning codeql delete java --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |

### Create a CodeQL variant analysis (gh secure-kit code-scanning codeql variant-analyses create)

```sh
gh secure-kit code-scanning codeql variant-analyses create --language <language> --query-pack <file> [--repositories <list> | --repository-owners <list> | --repository-lists <list>] [flags]
```

Creates a new CodeQL variant analysis, which runs a CodeQL query against one or more repositories. `--repo` specifies the controller repository that runs the GitHub Actions workflow and stores the results. Exactly one of `--repositories`, `--repository-owners` or `--repository-lists` must be specified.

```sh
# Run a query against a specific list of repositories
gh secure-kit code-scanning codeql variant-analyses create \
  --repo my-org/controller-repo \
  --language csharp \
  --query-pack ./query-pack.zip \
  --repositories octocat/Hello-World,octocat/example

# Run a query against all repositories owned by an organization
gh secure-kit code-scanning codeql variant-analyses create \
  --repo my-org/controller-repo \
  --language javascript \
  --query-pack ./query-pack.zip \
  --repository-owners octocat
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--language` | | | The CodeQL query language (required) |
| `--query-pack` | | | Path to a zipped CodeQL query pack file to upload (required) |
| `--repo` | `-R` | `""` | The controller repository in the format 'owner/repo' |
| `--repositories` | | | Repositories to analyze, in 'owner/repo' format (comma-separated) |
| `--repository-lists` | | | Names of repository lists to analyze (comma-separated) |
| `--repository-owners` | | | Organizations or users whose repositories to analyze (comma-separated) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get the summary of a CodeQL variant analysis (gh secure-kit code-scanning codeql variant-analyses get)

```sh
gh secure-kit code-scanning codeql variant-analyses get <variant-analysis-id> [flags]
```

Gets the summary of a CodeQL variant analysis for the controller repository.

```sh
gh secure-kit code-scanning codeql variant-analyses get 123 --repo my-org/controller-repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The controller repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get the analysis status of a repository in a CodeQL variant analysis (gh secure-kit code-scanning codeql variant-analyses repo-status)

```sh
gh secure-kit code-scanning codeql variant-analyses repo-status <variant-analysis-id> --target-repo <owner/repo> [flags]
```

Gets the analysis status of a specific repository that was scanned as part of a CodeQL variant analysis.

```sh
gh secure-kit code-scanning codeql variant-analyses repo-status 123 \
  --repo my-org/controller-repo \
  --target-repo octocat/Hello-World
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The controller repository in the format 'owner/repo' |
| `--target-repo` | | | The scanned repository in the format 'owner/repo' (required) |
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

### Disable code scanning default setup for an organization (gh secure-kit code-scanning default-setup disable)

```sh
gh secure-kit code-scanning default-setup disable --owner <org>
```

Disable code scanning default setup for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

### Enable code scanning default setup for an organization (gh secure-kit code-scanning default-setup enable)

```sh
gh secure-kit code-scanning default-setup enable --owner <org> [--query-suite <suite>]
```

Enable code scanning default setup for all eligible repositories in an organization.
Use `--query-suite` to specify the CodeQL query suite (default or extended).

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |
| `--query-suite` | | `""` | CodeQL query suite {default\|extended} |

### Get a code scanning default setup configuration (gh secure-kit code-scanning default-setup get)

```sh
gh secure-kit code-scanning default-setup get [flags]
```

Gets the code scanning default setup configuration for a repository.

```sh
gh secure-kit code-scanning default-setup get --repo owner/repo
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Update a code scanning default setup configuration (gh secure-kit code-scanning default-setup update)

```sh
gh secure-kit code-scanning default-setup update --state <state> [flags]
```

Updates the code scanning default setup configuration for a repository.

```sh
# Enable default setup with specific languages
gh secure-kit code-scanning default-setup update --repo owner/repo --state configured --languages javascript-typescript,python

# Disable default setup
gh secure-kit code-scanning default-setup update --repo owner/repo --state not-configured
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--languages` | | | CodeQL languages to be analyzed (comma-separated, defaults to auto-detected languages) |
| `--query-suite` | | `""` | CodeQL query suite to be used {default\|extended} |
| `--repo` | `-R` | `""` | The repository in the format 'owner/repo' |
| `--state` | | | The desired state of code scanning default setup (required) {configured\|not-configured} |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

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

### Create security advisory (gh secure-kit security-advisories create)

```sh
gh secure-kit security-advisories create --summary <text> --description <text> --ecosystem <ecosystem> [--repo <owner/repo>] [--cve-id <id>] [--severity <severity>] [--cvss-vector-string <string>] [--package-name <name>] [--vulnerable-version-range <range>] [--patched-versions <versions>] [--cwe-ids <ids>] [--start-private-fork]
```

Create a new repository security advisory. Requires `--summary`, `--description`, and `--ecosystem`.

### Get global security advisory (gh secure-kit security-advisories global get)

```sh
gh secure-kit security-advisories global get <ghsa-id>
```

Get a global security advisory from the GitHub Advisory Database by its GHSA identifier.

### Get security advisory (gh secure-kit security-advisories get)

```sh
gh secure-kit security-advisories get <ghsa-id> [--repo <owner/repo>]
```

Get a repository security advisory by its GHSA identifier.

### List global security advisories (gh secure-kit security-advisories global list)

```sh
gh secure-kit security-advisories global list [--type <type>] [--severity <severity>] [--ecosystem <ecosystem>] [--ghsa-id <id>] [--cve-id <id>]
```

List global security advisories from the GitHub Advisory Database. Filter by type, severity, ecosystem, GHSA ID, or CVE ID.

### List security advisories (gh secure-kit security-advisories list)

```sh
gh secure-kit security-advisories list [--repo <owner/repo>] [--owner <org>] [--state <state>] [--sort <field>] [--direction <asc|desc>]
```

List repository security advisories for a repository or organization. Use `--owner` for org-wide listing.

### Report vulnerability in a repository (gh secure-kit security-advisories report)

```sh
gh secure-kit security-advisories report --summary <text> --description <text> --ecosystem <ecosystem> [--repo <owner/repo>] [--package-name <name>] [--severity <severity>] [--cvss-vector-string <string>] [--cwe-ids <ids>] [--start-private-fork]
```

Report a vulnerability in an open source repository to the maintainers privately. Requires `--summary`, `--description`, and `--ecosystem`.

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

### Disable secret scanning for an organization (gh secure-kit secret-scanning disable)

```sh
gh secure-kit secret-scanning disable --owner <org>
```

Disable secret scanning for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

### Enable secret scanning for an organization (gh secure-kit secret-scanning enable)

```sh
gh secure-kit secret-scanning enable --owner <org>
```

Enable secret scanning for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

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

### Disable secret scanning push protection for an organization (gh secure-kit secret-scanning push-protection disable)

```sh
gh secure-kit secret-scanning push-protection disable --owner <org>
```

Disable secret scanning push protection for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

### Enable secret scanning push protection for an organization (gh secure-kit secret-scanning push-protection enable)

```sh
gh secure-kit secret-scanning push-protection enable --owner <org>
```

Enable secret scanning push protection for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

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

### Scan local git content for secrets (gh secure-kit secret-scanning local check)

```sh
gh secure-kit secret-scanning local check [flags]
```

Scan local git content for secrets using built-in and user-defined patterns. Exactly one target must be selected: `--unpushed` (default), `--staged`, `--uncommitted`, `--rev-range`, or `--no-git`. This is an independent, offline reimplementation and does not use GitHub's official secret scanning patterns. Exits with status 1 if any secret is found.

```sh
# Scan commits reachable from HEAD but not pushed to any remote (default)
gh secure-kit secret-scanning local check

# Scan a specific directory without using git
gh secure-kit secret-scanning local check --path ./some-dir --no-git

# Scan an explicit revision range and output JSON
gh secure-kit secret-scanning local check --rev-range main..HEAD --format json

# Filter patterns using the organization's secret scanning pattern configuration
gh secure-kit secret-scanning local check --owner my-org --pattern-config
```

### List local secret scanning patterns (gh secure-kit secret-scanning local patterns)

```sh
gh secure-kit secret-scanning local patterns [flags]
```

List the built-in and user-defined secret scanning patterns used by `secret-scanning local check`, including whether each is enabled.

```sh
# List all local secret scanning patterns
gh secure-kit secret-scanning local patterns

# Filter patterns using the organization's secret scanning pattern configuration
gh secure-kit secret-scanning local patterns --owner my-org --pattern-config
```

### Install git hooks that run local secret scanning (gh secure-kit secret-scanning local hook install)

```sh
gh secure-kit secret-scanning local hook install [pre-commit|pre-push]... [flags]
```

Install git hooks that run `secret-scanning local check` before a commit or a push. Only the pre-push hook is installed when no hook name is given, which is enough to stop a secret from reaching the remote. The pre-commit hook scans staged changes and the pre-push hook scans the exact commits being pushed (read from the refs git supplies on stdin, so pushes of a branch other than the checked-out one are also covered), aborting the operation when a secret is found. For a new branch the hook excludes commits already on the destination remote using its local remote-tracking refs, so keep them current with `git fetch`; pushing to a remote that has never been fetched (or by URL) falls back to scanning the branch's full history, which may require raising `--max-commits`. An existing hook that was not generated by this tool is kept unless `--force` (overwrite) or `--backup` (move aside to `<hook>.gh-secure-kit.bak`) is given. The `core.hooksPath` configuration is honored when resolving the hooks directory.

```sh
# Install the pre-push hook
gh secure-kit secret-scanning local hook install

# Install both the pre-commit and pre-push hooks
gh secure-kit secret-scanning local hook install pre-commit pre-push

# Move an existing hook aside before installing
gh secure-kit secret-scanning local hook install --backup
```

### Show the local secret scanning git hook status (gh secure-kit secret-scanning local hook status)

```sh
gh secure-kit secret-scanning local hook status [flags]
```

Show whether each supported git hook is installed. A hook is reported as `installed` when it was generated by this tool, `unmanaged` when a different hook script is present, and `not_installed` when no hook file exists.

```sh
gh secure-kit secret-scanning local hook status

# Output as JSON
gh secure-kit secret-scanning local hook status --format json
```

### Remove git hooks that run local secret scanning (gh secure-kit secret-scanning local hook uninstall)

```sh
gh secure-kit secret-scanning local hook uninstall [pre-commit|pre-push]... [flags]
```

Remove the git hooks installed by `secret-scanning local hook install`. Every supported hook is removed when no hook name is given. A hook that was not generated by this tool is kept unless `--force` is given.

```sh
# Remove both the pre-commit and pre-push hooks
gh secure-kit secret-scanning local hook uninstall

# Remove only the pre-commit hook
gh secure-kit secret-scanning local hook uninstall pre-commit
```

### Local secret scanning configuration file

Both `secret-scanning local check` and `secret-scanning local patterns` read an optional YAML configuration file. It is auto-discovered as `.gh-secure-kit-secret-scanning.yml` in the scanned directory, or specified explicitly with `--config`.

```yaml
patterns:
  - id: my_internal_token
    token_type: my_internal_token
    display_name: My Internal Token
    regex: 'mytoken_[0-9a-f]{32}'
    keywords:
      - mytoken_

allowlist:
  regexes:
    - '^ghp_0{36}$'
  paths:
    - internal/localscan/*_test.go
  commits:
    - 461e82a58c0cd9484db7014ba8937022563745d9
  stopwords:
    - EXAMPLE
    - dummy
```

`patterns` entries are merged with the built-in patterns; an entry whose `id` matches a built-in pattern replaces that built-in definition. `id` and `regex` are required, `token_type`, `display_name` and `keywords` are optional. `keywords` acts as a case-insensitive pre-filter: the regex is only evaluated when the content contains at least one keyword.

`allowlist` entries suppress findings, and a finding is suppressed if any single entry matches:

- `regexes`: Go (RE2) regular expressions evaluated against the matched secret text
- `paths`: glob pattern (`filepath.Match`) or substring match against the file path
- `commits`: full commit SHA, exact match
- `stopwords`: literal substrings checked against the whole line containing the match

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

## Repository Security Feature Toggles

### Disable automated security fixes for a repository (gh secure-kit repo automated-security-fixes disable)

```sh
gh secure-kit repo automated-security-fixes disable [--owner <org>] [--repo <owner/repo>]
```

Disable automated security fixes for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |
| `--repo` | `-R` | | The repository in the format 'owner/repo' (optional) |

### Disable private vulnerability reporting for a repository (gh secure-kit repo private-vulnerability-reporting disable)

```sh
gh secure-kit repo private-vulnerability-reporting disable [--owner <org>] [--repo <owner/repo>]
```

Disable private vulnerability reporting for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |
| `--repo` | `-R` | | The repository in the format 'owner/repo' (optional) |

### Disable vulnerability alerts for a repository (gh secure-kit repo vulnerability-alerts disable)

```sh
gh secure-kit repo vulnerability-alerts disable [--owner <org>] [--repo <owner/repo>]
```

Disable vulnerability alerts for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |
| `--repo` | `-R` | | The repository in the format 'owner/repo' (optional) |

### Enable automated security fixes for a repository (gh secure-kit repo automated-security-fixes enable)

```sh
gh secure-kit repo automated-security-fixes enable [--owner <org>] [--repo <owner/repo>]
```

Enable automated security fixes for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |
| `--repo` | `-R` | | The repository in the format 'owner/repo' (optional) |

### Enable private vulnerability reporting for a repository (gh secure-kit repo private-vulnerability-reporting enable)

```sh
gh secure-kit repo private-vulnerability-reporting enable [--owner <org>] [--repo <owner/repo>]
```

Enable private vulnerability reporting for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |
| `--repo` | `-R` | | The repository in the format 'owner/repo' (optional) |

### Enable vulnerability alerts for a repository (gh secure-kit repo vulnerability-alerts enable)

```sh
gh secure-kit repo vulnerability-alerts enable [--owner <org>] [--repo <owner/repo>]
```

Enable vulnerability alerts for a repository.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |
| `--repo` | `-R` | | The repository in the format 'owner/repo' (optional) |

### Get the status of automated security fixes for a repository (gh secure-kit repo automated-security-fixes status)

```sh
gh secure-kit repo automated-security-fixes status [--owner <org>] [--repo <owner/repo>]
```

Get the status of automated security fixes for a repository, including whether it is enabled and paused.

```sh
gh secure-kit repo automated-security-fixes status --repo owner/repo

# Output as JSON
gh secure-kit repo automated-security-fixes status --repo owner/repo --format json
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | | The organization name (optional) |
| `--repo` | `-R` | | The repository in the format 'owner/repo' (optional) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get the status of private vulnerability reporting for a repository (gh secure-kit repo private-vulnerability-reporting status)

```sh
gh secure-kit repo private-vulnerability-reporting status [--owner <org>] [--repo <owner/repo>]
```

Get the status of private vulnerability reporting for a repository.

```sh
gh secure-kit repo private-vulnerability-reporting status --repo owner/repo

# Output as JSON
gh secure-kit repo private-vulnerability-reporting status --repo owner/repo --format json
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | | The organization name (optional) |
| `--repo` | `-R` | | The repository in the format 'owner/repo' (optional) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

### Get the status of vulnerability alerts for a repository (gh secure-kit repo vulnerability-alerts status)

```sh
gh secure-kit repo vulnerability-alerts status [--owner <org>] [--repo <owner/repo>]
```

Get the status of vulnerability alerts for a repository.

```sh
gh secure-kit repo vulnerability-alerts status --repo owner/repo

# Output as JSON
gh secure-kit repo vulnerability-alerts status --repo owner/repo --format json
```

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--format` | | | Output format: {json} |
| `--jq` | `-q` | | Filter JSON output using a jq expression |
| `--owner` | `-o` | | The organization name (optional) |
| `--repo` | `-R` | | The repository in the format 'owner/repo' (optional) |
| `--template` | `-t` | | Format JSON output using a Go template; see "gh help formatting" |

## Advanced Security

### Disable GitHub Advanced Security for an organization (gh secure-kit advanced-security disable)

```sh
gh secure-kit advanced-security disable --owner <org>
```

Disable GitHub Advanced Security for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |

### Enable GitHub Advanced Security for an organization (gh secure-kit advanced-security enable)

```sh
gh secure-kit advanced-security enable --owner <org>
```

Enable GitHub Advanced Security for all eligible repositories in an organization.

**Flags:**

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--owner` | `-o` | | The organization name (optional) |
