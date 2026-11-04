package gcpperms

import "testing"

func TestV2Name(t *testing.T) {
	tests := map[string]struct {
		perm, want string
	}{
		"service is the domain's label": {
			perm: "iam.roles.delete", want: "iam.googleapis.com/roles.delete",
		},
		// spec: deny_names.go has the services whose domain differs.
		"resourcemanager": {
			perm: "resourcemanager.projects.delete",
			want: "cloudresourcemanager.googleapis.com/projects.delete",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, V2Name(tc.perm), tc.want)
		})
	}
}

func TestApplyDenials(t *testing.T) {
	const ada = "user:ada@example.com"
	rule := func(principals []string, perms ...string) DenyRule {
		return DenyRule{Policy: "p", DeniedPrincipals: principals, DeniedPermissions: perms}
	}
	everyone := []string{"principalSet://goog/public:all"}
	tests := map[string]struct {
		member string
		rules  []DenyRule
		// want is the permissions left, and the denials.
		wantPerms []string
		want      []Denial
	}{
		"no rules": {
			member:    ada,
			wantPerms: []string{"pubsub.topics.get", "pubsub.topics.list"},
		},
		"denied to the user": {
			member: ada,
			rules: []DenyRule{
				rule(
					[]string{"principal://goog/subject/ada@example.com"},
					"pubsub.googleapis.com/topics.list",
				),
			},
			wantPerms: []string{"pubsub.topics.get"},
			want:      []Denial{{Permission: "pubsub.topics.list", Policy: "p", Certain: true}},
		},
		"denied to another user": {
			member: ada,
			rules: []DenyRule{
				rule(
					[]string{"principal://goog/subject/bob@example.com"},
					"pubsub.googleapis.com/topics.list",
				),
			},
			wantPerms: []string{"pubsub.topics.get", "pubsub.topics.list"},
		},
		"a bare email matches a service account": {
			member: "app@demo.iam.gserviceaccount.com",
			rules: []DenyRule{
				rule(
					[]string{
						"principal://iam.googleapis.com/projects/-/serviceAccounts/app@demo.iam.gserviceaccount.com",
					},
					"pubsub.googleapis.com/topics.get",
				),
			},
			wantPerms: []string{"pubsub.topics.list"},
			want:      []Denial{{Permission: "pubsub.topics.get", Policy: "p", Certain: true}},
		},
		"a user may be in a group": {
			member: ada,
			rules: []DenyRule{
				rule(
					[]string{"principalSet://goog/group/eng@example.com"},
					"pubsub.googleapis.com/*.*",
				),
			},
			wantPerms: []string{"pubsub.topics.get", "pubsub.topics.list"},
			want: []Denial{
				{
					Permission: "pubsub.topics.get",
					Policy:     "p",
					Reason:     "denied to a set of principals the member may be in",
				},
				{
					Permission: "pubsub.topics.list",
					Policy:     "p",
					Reason:     "denied to a set of principals the member may be in",
				},
			},
		},
		"the group itself": {
			member: "group:eng@example.com",
			rules: []DenyRule{
				rule(
					[]string{"principalSet://goog/group/eng@example.com"},
					"pubsub.googleapis.com/*.get",
				),
			},
			wantPerms: []string{"pubsub.topics.list"},
			want:      []Denial{{Permission: "pubsub.topics.get", Policy: "p", Certain: true}},
		},
		"an exception for the member": {
			member: ada,
			rules: []DenyRule{{
				Policy:              "p",
				DeniedPrincipals:    everyone,
				ExceptionPrincipals: []string{"principal://goog/subject/ada@example.com"},
				DeniedPermissions:   []string{"pubsub.googleapis.com/topics.*"},
			}},
			wantPerms: []string{"pubsub.topics.get", "pubsub.topics.list"},
		},
		"an excepted permission, and a condition": {
			member: ada,
			rules: []DenyRule{{
				Policy:               "p",
				DeniedPrincipals:     everyone,
				DeniedPermissions:    []string{"pubsub.googleapis.com/topics.*"},
				ExceptionPermissions: []string{"pubsub.googleapis.com/topics.get"},
				DenialCondition:      &Condition{Title: "Production only"},
			}},
			wantPerms: []string{"pubsub.topics.get", "pubsub.topics.list"},
			want: []Denial{
				{
					Permission: "pubsub.topics.list",
					Policy:     "p",
					Reason:     "only when Production only holds",
				},
			},
		},
		"a rule that does not apply is passed over": {
			member: ada,
			rules: []DenyRule{
				rule(
					[]string{"principal://goog/subject/bob@example.com"},
					"pubsub.googleapis.com/topics.list",
				),
				{
					Policy:            "q",
					DeniedPrincipals:  everyone,
					DeniedPermissions: []string{"pubsub.googleapis.com/topics.list"},
				},
			},
			wantPerms: []string{"pubsub.topics.get"},
			want:      []Denial{{Permission: "pubsub.topics.list", Policy: "q", Certain: true}},
		},
		"a set this cannot resolve may hold the member": {
			member: ada,
			rules: []DenyRule{
				rule(
					[]string{"principalSet://goog/cloudIdentityCustomerId/C01"},
					"pubsub.googleapis.com/topics.list",
				),
			},
			wantPerms: []string{"pubsub.topics.get", "pubsub.topics.list"},
			want: []Denial{{
				Permission: "pubsub.topics.list",
				Policy:     "p",
				Reason:     "denied to a set of principals the member may be in",
			}},
		},
		"the first possible rule is kept": {
			member: ada,
			rules: []DenyRule{
				rule(
					[]string{"principalSet://goog/group/eng@example.com"},
					"pubsub.googleapis.com/topics.list",
				),
				{
					Policy:            "q",
					DeniedPrincipals:  everyone,
					DeniedPermissions: []string{"pubsub.googleapis.com/topics.list"},
					DenialCondition:   &Condition{Expression: "resource.hasTagKey('env')"},
				},
			},
			wantPerms: []string{"pubsub.topics.get", "pubsub.topics.list"},
			want: []Denial{{
				Permission: "pubsub.topics.list",
				Policy:     "p",
				Reason:     "denied to a set of principals the member may be in",
			}},
		},
		"an exception for a group the member may be in": {
			member: ada,
			rules: []DenyRule{{
				Policy:              "p",
				DeniedPrincipals:    everyone,
				ExceptionPrincipals: []string{"principalSet://goog/group/eng@example.com"},
				DeniedPermissions:   []string{"pubsub.googleapis.com/topics.get"},
			}},
			wantPerms: []string{"pubsub.topics.get", "pubsub.topics.list"},
			want: []Denial{{
				Permission: "pubsub.topics.get",
				Policy:     "p",
				Reason:     "except for a set of principals the member may be in",
			}},
		},
		"a workforce identity written as the member is": {
			member: "principal://iam.googleapis.com/locations/global/workforcePools/staff/subject/ada",
			rules: []DenyRule{
				rule(
					[]string{
						"principal://iam.googleapis.com/locations/global/workforcePools/STAFF/subject/ada",
						"principal://iam.googleapis.com/locations/global/workforcePools/staff/subject/bob",
					},
					"pubsub.googleapis.com/topics.get",
				),
			},
			wantPerms: []string{"pubsub.topics.list"},
			want:      []Denial{{Permission: "pubsub.topics.get", Policy: "p", Certain: true}},
		},
		"another workforce identity": {
			member: ada,
			rules: []DenyRule{
				rule(
					[]string{
						"principal://iam.googleapis.com/locations/global/workforcePools/staff/subject/ada@example.com",
					},
					"pubsub.googleapis.com/topics.get",
				),
			},
			wantPerms: []string{"pubsub.topics.get", "pubsub.topics.list"},
		},
		"a workload identity is no service account": {
			member: "serviceAccount:app@demo.iam.gserviceaccount.com",
			rules: []DenyRule{
				rule(
					[]string{
						"principal://iam.googleapis.com/projects/1/locations/global/" +
							"workloadIdentityPools/pool/subject/app@demo.iam.gserviceaccount.com",
					},
					"pubsub.googleapis.com/topics.get",
				),
			},
			wantPerms: []string{"pubsub.topics.get", "pubsub.topics.list"},
		},
		"a user is in no other user": {
			member: ada,
			rules: []DenyRule{{
				Policy:              "p",
				DeniedPrincipals:    everyone,
				ExceptionPrincipals: []string{"principal://goog/subject/bob@example.com"},
				DeniedPermissions:   []string{"pubsub.googleapis.com/topics.get"},
			}},
			wantPerms: []string{"pubsub.topics.list"},
			want:      []Denial{{Permission: "pubsub.topics.get", Policy: "p", Certain: true}},
		},
		"a certain rule wins over a possible one": {
			member: ada,
			rules: []DenyRule{
				rule(
					[]string{"principalSet://goog/cloudIdentityCustomerId/C01"},
					"pubsub.googleapis.com/topics.list",
				),
				{
					Policy:            "q",
					DeniedPrincipals:  everyone,
					DeniedPermissions: []string{"pubsub.googleapis.com/topics.list"},
				},
			},
			wantPerms: []string{"pubsub.topics.get"},
			want:      []Denial{{Permission: "pubsub.topics.list", Policy: "q", Certain: true}},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			access := MemberAccess{
				Member:                 tc.member,
				Permissions:            []string{"pubsub.topics.get"},
				ConditionalPermissions: []string{"pubsub.topics.list"},
			}
			got := Policy{DenyPolicies: len(tc.rules), DenyRules: tc.rules}.ApplyDenials(&access)
			equals(t, append(got.Permissions, got.ConditionalPermissions...), tc.wantPerms)
			equals(t, got.Denials, tc.want)
			equals(t, got.DenyPolicies, len(tc.rules))
			// spec: ApplyDenials returns a new value; access is unchanged.
			equals(t, access.Permissions, []string{"pubsub.topics.get"})
		})
	}
}
