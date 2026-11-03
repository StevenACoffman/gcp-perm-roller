package gcpperms

//go:generate go run ./gensupport

const (
	// Supported permissions work in custom roles.
	Supported SupportLevel = "SUPPORTED"
	// Testing permissions can be put in a custom role, but Google is still
	// checking that they work there, so they may behave unexpectedly.
	Testing SupportLevel = "TESTING"
	// NotSupported permissions cannot be put in a custom role: creating or
	// updating one that includes them fails.
	NotSupported SupportLevel = "NOT_SUPPORTED"
)

// SupportLevel says whether a permission can be put in a custom role.
type SupportLevel string

// CustomRoleSupport returns perm's support level in custom roles, from
// Google's list of support levels as it was when support_levels.go was
// generated. A permission newer than that list is reported Supported.
//
// The list, customRoleSupport, is generated data like TableSource, read
// here and nowhere else; `go generate` refreshes it.
func CustomRoleSupport(perm string) SupportLevel {
	if level, ok := customRoleSupport[perm]; ok {
		return level
	}
	return Supported
}
