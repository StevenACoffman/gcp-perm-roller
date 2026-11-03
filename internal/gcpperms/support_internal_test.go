package gcpperms

import (
	"bytes"
	"maps"
	"slices"
	"strings"
	"testing"
)

// supportExample returns a permission the generated list gives level, so
// the tests follow the list as Google changes it.
func supportExample(t *testing.T, level SupportLevel) string {
	t.Helper()
	for _, perm := range slices.Sorted(maps.Keys(customRoleSupport)) {
		if customRoleSupport[perm] == level {
			return perm
		}
	}
	t.Fatalf("support_levels.go lists no %s permission", level)
	return ""
}

func TestCustomRoleSupport(t *testing.T) {
	tests := map[string]struct {
		perm string
		want SupportLevel
	}{
		"not supported": {perm: supportExample(t, NotSupported), want: NotSupported},
		"testing":       {perm: supportExample(t, Testing), want: Testing},
		// spec: a permission the list does not name is supported.
		"unlisted": {perm: "datastore.entities.get", want: Supported},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, CustomRoleSupport(tc.perm), tc.want)
		})
	}
}

func TestWriteRolesMarksSupportLevels(t *testing.T) {
	unsupported := supportExample(t, NotSupported)
	trial := supportExample(t, Testing)
	bins := []Binary{{Package: "example.com/one", Calls: []Call{{
		API:         "cloud.google.com/go/x.Client.Do",
		Mapped:      true,
		Permissions: []string{"datastore.entities.get", unsupported},
		Conditional: []string{trial},
	}}}}
	var buf bytes.Buffer
	ok(t, WriteRoles(&buf, bins))
	// spec: an unsupported permission is commented out, since gcloud would
	// reject the role; a testing one stays, marked, beside its other notes.
	for _, want := range []string{
		"- datastore.entities.get\n",
		"# - " + unsupported + " # not supported in custom roles\n",
		"- " + trial + " # conditional; testing in custom roles\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("role lacks %q:\n%s", want, buf.String())
		}
	}
}

func TestSelectRolesReportsSupportOfUncovered(t *testing.T) {
	unsupported := supportExample(t, NotSupported)
	trial := supportExample(t, Testing)
	sel := SelectRoles([]string{"nope.x.y", unsupported, trial}, nil, RoleFilter{})
	equals(t, sel.Uncovered, slices.Sorted(slices.Values([]string{"nope.x.y", unsupported, trial})))
	// spec: only the uncovered permissions a custom role cannot fully hold
	// get a level.
	equals(t, sel.CustomRoleSupport, map[string]SupportLevel{
		unsupported: NotSupported,
		trial:       Testing,
	})

	var buf bytes.Buffer
	ok(t, WritePredefinedRoles(&buf, []Binary{{Package: "p", PredefinedRoles: &sel}}))
	for _, want := range []string{
		"    nope.x.y\n",
		unsupported + " ",
		"not supported in custom roles\n",
		"testing in custom roles\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, buf.String())
		}
	}
}
