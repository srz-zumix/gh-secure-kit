package cmd

import (
	"github.com/spf13/cobra"
	auditlog "github.com/srz-zumix/gh-secure-kit/cmd/audit_log"
)

func init() {
	rootCmd.AddCommand(NewAuditLogCmd())
}

// NewAuditLogCmd returns the audit-log parent command.
func NewAuditLogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit-log",
		Short: "Inspect organization audit logs for security-related operations",
	}
	cmd.AddCommand(auditlog.NewCredentialsCmd())
	return cmd
}
