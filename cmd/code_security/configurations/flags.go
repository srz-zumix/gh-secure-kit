package configurations

import (
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

// addConfigFeatureFlags binds enum/string feature flags shared by create and update commands.
// On create, name and description are required by the API; the caller is responsible for marking them.
func addConfigFeatureFlags(cmd *cobra.Command, opts *gh.CodeSecurityConfigurationOptions) {
	f := cmd.Flags()
	f.StringVar(&opts.Name, "name", "", "The name of the code security configuration")
	f.StringVar(&opts.Description, "description", "", "A description of the code security configuration")
	cmdutil.StringEnumFlag(cmd, &opts.AdvancedSecurity, "advanced-security", "", "", gh.CodeSecurityAdvancedSecurityStates, "Enablement status of GitHub Advanced Security")
	cmdutil.StringEnumFlag(cmd, &opts.CodeSecurity, "code-security", "", "", gh.CodeSecurityFeatureStates, "Enablement status of GitHub Code Security features")
	cmdutil.StringEnumFlag(cmd, &opts.SecretProtection, "secret-protection", "", "", gh.CodeSecurityFeatureStates, "Enablement status of GitHub Secret Protection features")
	cmdutil.StringEnumFlag(cmd, &opts.DependencyGraph, "dependency-graph", "", "", gh.CodeSecurityFeatureStates, "Enablement status of Dependency Graph")
	cmdutil.StringEnumFlag(cmd, &opts.DependencyGraphAutosubmitAction, "dependency-graph-autosubmit-action", "", "", gh.CodeSecurityFeatureStates, "Enablement status of automatic dependency submission")
	cmdutil.StringEnumFlag(cmd, &opts.DependabotAlerts, "dependabot-alerts", "", "", gh.CodeSecurityFeatureStates, "Enablement status of Dependabot alerts")
	cmdutil.StringEnumFlag(cmd, &opts.DependabotSecurityUpdates, "dependabot-security-updates", "", "", gh.CodeSecurityFeatureStates, "Enablement status of Dependabot security updates")
	cmdutil.StringEnumFlag(cmd, &opts.CodeScanningDefaultSetup, "code-scanning-default-setup", "", "", gh.CodeSecurityFeatureStates, "Enablement status of code scanning default setup")
	cmdutil.StringEnumFlag(cmd, &opts.CodeScanningDelegatedAlertDismissal, "code-scanning-delegated-alert-dismissal", "", "", gh.CodeSecurityFeatureStates, "Enablement status of code scanning delegated alert dismissal")
	cmdutil.StringEnumFlag(cmd, &opts.SecretScanning, "secret-scanning", "", "", gh.CodeSecurityFeatureStates, "Enablement status of secret scanning")
	cmdutil.StringEnumFlag(cmd, &opts.SecretScanningPushProtection, "secret-scanning-push-protection", "", "", gh.CodeSecurityFeatureStates, "Enablement status of secret scanning push protection")
	cmdutil.StringEnumFlag(cmd, &opts.SecretScanningDelegatedBypass, "secret-scanning-delegated-bypass", "", "", gh.CodeSecurityFeatureStates, "Enablement status of secret scanning delegated bypass")
	cmdutil.StringEnumFlag(cmd, &opts.SecretScanningValidityChecks, "secret-scanning-validity-checks", "", "", gh.CodeSecurityFeatureStates, "Enablement status of secret scanning validity checks")
	cmdutil.StringEnumFlag(cmd, &opts.SecretScanningNonProviderPatterns, "secret-scanning-non-provider-patterns", "", "", gh.CodeSecurityFeatureStates, "Enablement status of secret scanning non-provider patterns")
	cmdutil.StringEnumFlag(cmd, &opts.SecretScanningGenericSecrets, "secret-scanning-generic-secrets", "", "", gh.CodeSecurityFeatureStates, "Enablement status of Copilot secret scanning")
	cmdutil.StringEnumFlag(cmd, &opts.SecretScanningDelegatedAlertDismissal, "secret-scanning-delegated-alert-dismissal", "", "", gh.CodeSecurityFeatureStates, "Enablement status of secret scanning delegated alert dismissal")
	cmdutil.StringEnumFlag(cmd, &opts.PrivateVulnerabilityReporting, "private-vulnerability-reporting", "", "", gh.CodeSecurityFeatureStates, "Enablement status of private vulnerability reporting")
	cmdutil.StringEnumFlag(cmd, &opts.Enforcement, "enforcement", "", "", gh.CodeSecurityEnforcementStates, "Enforcement status for the configuration")
}
