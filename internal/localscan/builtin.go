package localscan

import "regexp"

// pemKeyBody requires an actual base64 key body after a PEM header, so that a
// bare header mention in source, docs or tests is not reported.
const pemKeyBody = `[\s\S]{0,200}?\n[A-Za-z0-9+/=]{40,}`

// BuiltinPatterns returns the built-in secret detection patterns. These are
// independent reimplementations, not GitHub's official provider patterns,
// since GitHub does not publish those regular expressions.
func BuiltinPatterns() []Pattern {
	return []Pattern{
		mustPattern("github_personal_access_token", "github_token", "GitHub Personal Access Token", `ghp_[0-9A-Za-z]{36}`),
		mustPattern("github_fine_grained_pat", "github_fine_grained_pat", "GitHub Fine-grained Personal Access Token", `github_pat_[0-9A-Za-z_]{22,255}`),
		mustPattern("github_oauth_token", "github_oauth_token", "GitHub OAuth Access Token", `gho_[0-9A-Za-z]{36}`),
		mustPattern("github_app_token", "github_app_token", "GitHub App Installation Access Token", `ghs_[0-9A-Za-z]{36}`),
		mustPattern("github_refresh_token", "github_refresh_token", "GitHub Refresh Token", `ghr_[0-9A-Za-z]{36}`),
		mustPattern("aws_access_key_id", "aws_access_key_id", "AWS Access Key ID", `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		mustPattern("aws_secret_access_key", "aws_secret_access_key", "AWS Secret Access Key", `(?i)aws.{0,20}?(secret|access)?_?key.{0,20}?['"]\s*[:=]\s*['"][0-9a-zA-Z/+]{40}['"]`),
		mustPattern("google_api_key", "google_api_key", "Google API Key", `AIza[0-9A-Za-z\-_]{35}`),
		mustPattern("slack_token", "slack_token", "Slack Token", `xox[baprs]-[0-9A-Za-z-]{10,48}`),
		mustPattern("slack_webhook_url", "slack_webhook_url", "Slack Webhook URL", `https://hooks\.slack\.com/services/T[0-9A-Za-z]{8,10}/B[0-9A-Za-z]{8,10}/[0-9A-Za-z]{24}`),
		mustPattern("stripe_api_key", "stripe_api_key", "Stripe API Key", `(sk|rk)_(live|test)_[0-9a-zA-Z]{24,247}`),
		mustPattern("sendgrid_api_key", "sendgrid_api_key", "SendGrid API Key", `SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}`),
		mustPattern("npm_access_token", "npm_access_token", "NPM Access Token", `npm_[0-9A-Za-z]{36}`),
		mustPattern("pypi_api_token", "pypi_api_token", "PyPI API Token", `pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,1000}`),
		mustPattern("openai_api_key", "openai_api_key", "OpenAI API Key", `sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`),
		mustPattern("azure_storage_account_key", "azure_storage_account_key", "Azure Storage Account Key", `(?i)AccountKey=[0-9A-Za-z+/]{86}==`),
		mustPattern("rsa_private_key", "rsa_private_key", "RSA Private Key", `-----BEGIN RSA PRIVATE KEY-----`+pemKeyBody),
		mustPattern("openssh_private_key", "openssh_private_key", "OpenSSH Private Key", `-----BEGIN OPENSSH PRIVATE KEY-----`+pemKeyBody),
		mustPattern("pgp_private_key", "pgp_private_key", "PGP Private Key Block", `-----BEGIN PGP PRIVATE KEY BLOCK-----`+pemKeyBody),
		mustPattern("generic_private_key", "private_key", "Generic Private Key", `-----BEGIN (EC|DSA) PRIVATE KEY-----`+pemKeyBody),
		mustPattern("jwt", "jwt", "JSON Web Token", `eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}`),
	}
}

func mustPattern(id, tokenType, displayName, expr string) Pattern {
	return Pattern{
		ID:          id,
		TokenType:   tokenType,
		DisplayName: displayName,
		Regex:       regexp.MustCompile(expr),
		Source:      "builtin",
		Enabled:     true,
	}
}
