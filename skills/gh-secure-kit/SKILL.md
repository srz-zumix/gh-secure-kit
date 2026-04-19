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
