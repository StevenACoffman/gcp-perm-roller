package gcpperms

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/api/option"
	"pgregory.net/rapid"
)

func role(name string, perms ...string) Role {
	return Role{Name: name, Title: name, Stage: "GA", Permissions: perms}
}

func TestRoleFilterAllows(t *testing.T) {
	tests := map[string]struct {
		r      Role
		filter RoleFilter
		want   bool
	}{
		"GA role":                  {r: role("roles/datastore.user"), want: true},
		"BETA excluded by default": {r: Role{Name: "roles/x.y", Stage: "BETA"}},
		"BETA allowed explicitly": {
			r:      Role{Name: "roles/x.y", Stage: "BETA"},
			filter: RoleFilter{Stages: []string{"GA", "BETA"}},
			want:   true,
		},
		"GA excluded by stages": {
			r:      role("roles/x.y"),
			filter: RoleFilter{Stages: []string{"BETA"}},
		},
		"deprecated, even if listed": {
			r:      Role{Name: "roles/x.y", Stage: "DEPRECATED"},
			filter: RoleFilter{Stages: []string{"DEPRECATED"}},
		},
		"deleted": {
			r: Role{Name: "roles/x.y", Stage: "GA", Deleted: true},
		},
		"owner":   {r: role("roles/owner")},
		"editor":  {r: role("roles/editor")},
		"viewer":  {r: role("roles/viewer")},
		"browser": {r: role("roles/browser")},
		// spec: roles of no one service are as broad as the basic roles.
		"admin":                 {r: role("roles/admin")},
		"writer":                {r: role("roles/writer")},
		"reader":                {r: role("roles/reader")},
		"service agent by name": {r: role("roles/dataflow.serviceAgent")},
		"service agent by title": {
			r: Role{Name: "roles/x.agent", Title: "X Service Agent", Stage: "GA"},
		},
		"legacy":                 {r: role("roles/storage.legacyObjectReader")},
		"system":                 {r: role("roles/firebaserules.system")},
		"nested system":          {r: role("roles/x.internal.system")},
		"similar names are fine": {r: role("roles/x.systemAdmin"), want: true},
		// spec: a custom role is never recommended, even a GA one.
		"project custom role":      {r: role("projects/p/roles/CustomRole1")},
		"organization custom role": {r: role("organizations/1/roles/x")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, tc.filter.allows(&tc.r), tc.want)
		})
	}
}

func grantNames(sel RoleSelection) []string {
	var out []string
	for _, g := range sel.Grants {
		out = append(out, g.Role)
	}
	return out
}

func TestSelectRoles(t *testing.T) {
	roles := []Role{
		role("roles/datastore.viewer", "datastore.entities.get", "datastore.entities.list"),
		role(
			"roles/datastore.user",
			"datastore.entities.get",
			"datastore.entities.list",
			"datastore.entities.create",
			"datastore.entities.update",
			"datastore.entities.delete",
		),
		// Smaller than any Datastore role, but another product's.
		role("roles/firebase.thing", "datastore.entities.create", "datastore.entities.get"),
		role(
			"roles/storage.objectCreator",
			"storage.objects.create",
			"storage.multipart.create",
		),
		role("roles/storage.objectViewer", "storage.objects.get", "storage.objects.list"),
		role(
			"roles/storage.objectUser",
			"storage.objects.create",
			"storage.objects.get",
			"storage.objects.list",
			"storage.objects.delete",
			"storage.objects.update",
		),
		// The only role granting this permission belongs to another service.
		role("roles/dlp.user", "serviceusage.services.use", "dlp.jobs.create"),
		role("roles/owner", "secretmanager.versions.add"),
	}
	tests := map[string]struct {
		need          []string
		wantRoles     []string
		wantUncovered []string
		wantExcess    int
	}{
		"one role": {
			need: []string{
				"datastore.entities.get",
			},
			wantRoles:  []string{"roles/datastore.viewer"},
			wantExcess: 1,
		},
		"own service preferred over a smaller foreign role": {
			need:       []string{"datastore.entities.get", "datastore.entities.create"},
			wantRoles:  []string{"roles/datastore.user"},
			wantExcess: 3,
		},
		"two small roles beat one large one": {
			need: []string{"storage.objects.create", "storage.objects.get"},
			wantRoles: []string{
				"roles/storage.objectCreator",
				"roles/storage.objectViewer",
			},
			wantExcess: 2,
		},
		"one role beats two of the same total size": {
			need: []string{
				"storage.objects.create",
				"storage.objects.get",
				"storage.objects.list",
				"storage.objects.delete",
			},
			wantRoles:  []string{"roles/storage.objectUser"},
			wantExcess: 1,
		},
		"foreign role when no own-service role grants it": {
			need: []string{
				"serviceusage.services.use",
			},
			wantRoles:  []string{"roles/dlp.user"},
			wantExcess: 1,
		},
		"basic roles never count": {
			need: []string{
				"secretmanager.versions.add",
			},
			wantUncovered: []string{"secretmanager.versions.add"},
		},
		"duplicates and several services": {
			need: []string{
				"storage.objects.get",
				"datastore.entities.list",
				"storage.objects.get",
				"nope.x.y",
			},
			wantRoles: []string{
				"roles/datastore.viewer",
				"roles/storage.objectViewer",
			},
			wantUncovered: []string{"nope.x.y"},
			wantExcess:    2,
		},
		"nothing required": {},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sel := SelectRoles(tc.need, roles, RoleFilter{})
			equals(t, grantNames(sel), tc.wantRoles)
			equals(t, sel.Uncovered, tc.wantUncovered)
			equals(t, sel.Excess, tc.wantExcess)
			equals(t, sel.Inexact, false)
		})
	}
}

func TestSelectRolesGrantDetails(t *testing.T) {
	r := Role{
		Name:        "roles/x.editor",
		Title:       "X Editor",
		Stage:       "GA",
		Permissions: []string{"x.b.get", "x.a.get", "x.c.get"},
	}
	sel := SelectRoles([]string{"x.c.get", "x.a.get"}, []Role{r}, RoleFilter{})
	equals(t, sel.Grants, []RoleGrant{{
		Role: "roles/x.editor", Title: "X Editor", Stage: "GA", Size: 3,
		Covers: []string{"x.a.get", "x.c.get"},
	}})
}

func TestSelectRolesPrunesRedundantRoles(t *testing.T) {
	tests := map[string]struct {
		roles      []Role
		need       []string
		want       []RoleGrant
		wantExcess int
	}{
		"own-service role whose permission a foreign chosen role holds": {
			roles: []Role{
				role("roles/pubsub.publisher", "pubsub.topics.publish"),
				// The only logging role also holds the Pub/Sub permission.
				role(
					"roles/logging.writer",
					"logging.logEntries.create",
					"pubsub.topics.publish",
				),
			},
			need: []string{"logging.logEntries.create", "pubsub.topics.publish"},
			want: []RoleGrant{
				{
					Role:  "roles/logging.writer",
					Title: "roles/logging.writer",
					Stage: "GA",
					Size:  2,
					Covers: []string{
						"logging.logEntries.create",
						"pubsub.topics.publish",
					},
				},
			},
		},
		"of two roles each redundant given the other, the larger goes": {
			roles: []Role{
				role("roles/a.one", "a.x.p", "b.x.q"),
				role("roles/b.two", "a.x.p", "b.x.q", "b.x.z"),
			},
			need: []string{"a.x.p", "b.x.q"},
			want: []RoleGrant{{
				Role: "roles/a.one", Title: "roles/a.one", Stage: "GA", Size: 2,
				Covers: []string{"a.x.p", "b.x.q"},
			}},
		},
		"several pruned, unrelated roles kept": {
			roles: []Role{
				role("roles/pubsub.publisher", "pubsub.topics.publish"),
				role("roles/pubsub.subscriber", "pubsub.subscriptions.consume"),
				role(
					"roles/logging.admin",
					"logging.logEntries.create",
					"pubsub.topics.publish",
					"pubsub.subscriptions.consume",
					"logging.x.y",
				),
				role(
					"roles/storage.objectViewer",
					"storage.objects.get",
					"storage.objects.list",
				),
			},
			need: []string{
				"logging.logEntries.create", "pubsub.subscriptions.consume",
				"pubsub.topics.publish", "storage.objects.get",
			},
			want: []RoleGrant{
				{
					Role:  "roles/logging.admin",
					Title: "roles/logging.admin",
					Stage: "GA",
					Size:  4,
					Covers: []string{
						"logging.logEntries.create",
						"pubsub.subscriptions.consume",
						"pubsub.topics.publish",
					},
				},
				{
					Role:   "roles/storage.objectViewer",
					Title:  "roles/storage.objectViewer",
					Stage:  "GA",
					Size:   2,
					Covers: []string{"storage.objects.get"},
				},
			},
			wantExcess: 2,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sel := SelectRoles(tc.need, tc.roles, RoleFilter{})
			equals(t, sel.Grants, tc.want)
			equals(t, sel.Excess, tc.wantExcess)
		})
	}
}

func TestSelectRolesGreedyForLargeGroups(t *testing.T) {
	// One permission per role plus a role spanning them all links every
	// permission into one group too large to solve exactly.
	var need []string
	var roles []Role
	all := role("roles/big.admin")
	for i := range maxExact + 5 {
		p := "big.things.p" + strings.Repeat("x", i)
		need = append(need, p)
		roles = append(roles, role("roles/big.r"+strings.Repeat("x", i), p))
		all.Permissions = append(all.Permissions, p)
	}
	roles = append(roles, all)
	sel := SelectRoles(need, roles, RoleFilter{})
	equals(t, sel.Inexact, true)
	// Greedy picks the role covering everything: fewest permissions per
	// newly covered one.
	equals(t, grantNames(sel), []string{"roles/big.admin"})
	equals(t, sel.Excess, 0)
}

// genRoleProblem draws a small selection problem: permissions across two
// services, and roles granting random subsets of them, some from the
// other service. Pools are small so roles overlap.
func genRoleProblem(t *rapid.T) (need []string, roles []Role) {
	perms := []string{"a.x.get", "a.x.list", "a.x.set", "a.y.get", "b.x.get", "b.x.set"}
	need = rapid.SliceOfN(rapid.SampledFrom(perms), 0, 6).Draw(t, "need")
	n := rapid.IntRange(0, 7).Draw(t, "roles")
	for i := range n {
		svc := rapid.SampledFrom([]string{"a", "b", "c"}).Draw(t, "service")
		r := Role{
			Name: "roles/" + svc + ".r" + string(rune('0'+i)),
			Stage: rapid.SampledFrom([]string{"GA", "GA", "BETA"}).
				Draw(t, "stage"),
			Permissions: rapid.SliceOfNDistinct(rapid.SampledFrom(append(perms, "a.z.extra", "c.z.extra")), 1, 5, rapid.ID[string]).
				Draw(t, "perms"),
		}
		roles = append(roles, r)
	}
	return need, roles
}

// bruteForce returns the lowest cost of any set of allowed roles covering
// every coverable permission, under the same-service rule, by trying every
// subset. It is the oracle for SelectRoles' exact search.
func bruteForce(need []string, roles []Role) (best cost, coverable map[string]bool) {
	var allowed []Role
	for _, r := range roles {
		if (RoleFilter{}).allows(&r) {
			allowed = append(allowed, r)
		}
	}
	// grants reports whether r may be used for p: same service, or no
	// same-service role grants p.
	grants := func(r Role, p string) bool {
		if !slices.Contains(r.Permissions, p) {
			return false
		}
		if roleService(r.Name) == serviceOf(p) {
			return true
		}
		for _, o := range allowed {
			if roleService(o.Name) == serviceOf(p) &&
				slices.Contains(o.Permissions, p) {
				return false
			}
		}
		return true
	}
	coverable = make(map[string]bool)
	for _, p := range need {
		for _, r := range allowed {
			if grants(r, p) {
				coverable[p] = true
			}
		}
	}
	found := false
	for mask := 0; mask < 1<<len(allowed); mask++ {
		var c cost
		covered := make(map[string]bool)
		for i, r := range allowed {
			if mask&(1<<i) == 0 {
				continue
			}
			c.size += len(r.Permissions)
			c.roles++
			for _, p := range need {
				if grants(r, p) {
					covered[p] = true
				}
			}
		}
		if len(covered) == len(coverable) && (!found || c.less(best)) {
			best, found = c, true
		}
	}
	return best, coverable
}

func selectionCost(sel RoleSelection) cost {
	var c cost
	for _, g := range sel.Grants {
		c.size += g.Size
		c.roles++
	}
	return c
}

func TestSelectRolesIsOptimal(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		need, roles := genRoleProblem(t)
		sel := SelectRoles(need, roles, RoleFilter{})
		bound, _ := bruteForce(need, roles)
		// spec: the chosen roles cost no more than the cheapest covering
		// set under the same-service rule; pruning only lowers the cost.
		if got := selectionCost(sel); bound.less(got) {
			t.Fatalf("cost %+v exceeds the optimum %+v", got, bound)
		}
	})
}

func TestSelectRolesCoversEverythingCoverable(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		need, roles := genRoleProblem(t)
		sel := SelectRoles(need, roles, RoleFilter{})
		_, coverable := bruteForce(need, roles)
		covered := make(map[string]bool)
		for _, g := range sel.Grants {
			for _, p := range g.Covers {
				covered[p] = true
			}
		}
		// spec: every required permission is either granted or reported
		// uncovered, never both, and only uncoverable ones are uncovered.
		for _, p := range need {
			if covered[p] == slices.Contains(sel.Uncovered, p) {
				t.Fatalf(
					"%s: covered=%v, uncovered=%v",
					p,
					covered[p],
					sel.Uncovered,
				)
			}
			equals(t, covered[p], coverable[p])
		}
		if !slices.IsSorted(sel.Uncovered) {
			t.Fatalf("uncovered %v not sorted", sel.Uncovered)
		}
	})
}

func TestSelectRolesGrantsOnlyAllowedRoles(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		need, roles := genRoleProblem(t)
		sel := SelectRoles(need, roles, RoleFilter{})
		byName := make(map[string]Role)
		for _, r := range roles {
			byName[r.Name] = r
		}
		for _, g := range sel.Grants {
			r := byName[g.Role]
			// spec: grants are allowed roles; each covers required
			// permissions the role holds; sizes are the role's.
			if !(RoleFilter{}).allows(&r) {
				t.Fatalf("granted disallowed role %s", g.Role)
			}
			equals(t, g.Size, len(r.Permissions))
			for _, p := range g.Covers {
				if !slices.Contains(r.Permissions, p) || !slices.Contains(need, p) {
					t.Fatalf(
						"%s covers %s, which it lacks or nothing needs",
						g.Role,
						p,
					)
				}
			}
		}
	})
}

func TestSelectRolesHasNoRedundantRole(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		need, roles := genRoleProblem(t)
		sel := SelectRoles(need, roles, RoleFilter{})
		byName := make(map[string]Role)
		for _, r := range roles {
			byName[r.Name] = r
		}
		// spec: dropping any chosen role leaves a required permission
		// ungranted by the full permissions of the others: no role is
		// redundant, and none is superseded by another chosen role.
		for i := range sel.Grants {
			left := make(map[string]bool)
			for j, g := range sel.Grants {
				if j != i {
					for _, p := range byName[g.Role].Permissions {
						left[p] = true
					}
				}
			}
			lost := false
			for _, p := range sel.Grants[i].Covers {
				lost = lost || !left[p]
			}
			if !lost {
				t.Fatalf(
					"%s is redundant in %v",
					sel.Grants[i].Role,
					grantNames(sel),
				)
			}
		}
	})
}

func TestSelectRolesIgnoresInputOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		need, roles := genRoleProblem(t)
		want := SelectRoles(need, roles, RoleFilter{})
		got := SelectRoles(rapid.Permutation(need).Draw(t, "need order"),
			rapid.Permutation(roles).Draw(t, "role order"), RoleFilter{})
		// spec: role names are unique, so the choice does not depend on
		// the order roles or permissions are listed in.
		equals(t, got, want)
	})
}

func TestSelectRolesCountsExcess(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		need, roles := genRoleProblem(t)
		sel := SelectRoles(need, roles, RoleFilter{})
		byName := make(map[string]Role)
		for _, r := range roles {
			byName[r.Name] = r
		}
		granted := make(map[string]bool)
		for _, g := range sel.Grants {
			for _, p := range byName[g.Role].Permissions {
				granted[p] = true
			}
		}
		excess := 0
		for p := range granted {
			if !slices.Contains(need, p) {
				excess++
			}
		}
		// spec: excess is what the roles grant beyond what is required.
		equals(t, sel.Excess, excess)
	})
}

func TestGreedyCoverCoversAll(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		need, roles := genRoleProblem(t)
		perms := slices.Compact(slices.Sorted(slices.Values(need)))
		var sets []bitset
		var rs []*Role
		covered := newBitset(len(perms))
		for i := range roles {
			s := newBitset(len(perms))
			for j, p := range perms {
				if slices.Contains(roles[i].Permissions, p) {
					s.add(j)
				}
			}
			if !s.empty() {
				sets, rs = append(sets, s), append(rs, &roles[i])
				covered.or(s)
			}
		}
		target := covered.members()
		picks := greedyCover(target, sets, rs)
		got := newBitset(len(perms))
		for _, i := range picks {
			got.or(sets[i])
		}
		// spec: the greedy choice covers every coverable permission.
		equals(t, got.intersectCount(covered), len(target))
		if !slices.IsSorted(picks) {
			t.Fatalf("picks %v not sorted", picks)
		}
	})
}

func TestBitset(t *testing.T) {
	b := newBitset(0)
	equals(t, b.empty(), true)
	b.add(3)
	b.add(70)
	equals(t, b.members(), []int{3, 70})
	equals(t, b.has(70), true)
	equals(t, b.has(4), false)
	equals(t, b.has(500), false)
	c := newBitset(0)
	c.add(70)
	equals(t, b.intersectCount(c), 1)
	b.andNot(c)
	equals(t, b.members(), []int{3})
	c.or(b)
	equals(t, c.members(), []int{3, 70})
}

func TestLoadRolesFromPath(t *testing.T) {
	roles, err := LoadRolesFromPath("testdata/roles")
	ok(t, err)
	equals(t, len(roles), 2)
	equals(t, roles[0].Name, "roles/datastore.user")
	equals(
		t,
		roles[0].Permissions,
		[]string{
			"datastore.entities.get",
			"datastore.entities.list",
			"datastore.entities.create",
		},
	)

	roles, err = LoadRolesFromPath("testdata/roles.json")
	ok(t, err)
	equals(t, roles, []Role{
		{
			Name:        "roles/a.viewer",
			Title:       "A Viewer",
			Stage:       "BETA",
			Permissions: []string{"a.things.get"},
		},
		{
			Name:        "roles/a.old",
			Title:       "A Old",
			Stage:       "GA",
			Deleted:     true,
			Permissions: []string{},
		},
	})

	empty := t.TempDir()
	bad := filepath.Join(t.TempDir(), "bad.json")
	ok(t, os.WriteFile(bad, []byte("{"), 0o644))
	badDir := t.TempDir()
	ok(t, os.WriteFile(filepath.Join(badDir, "r.json"), []byte("["), 0o644))
	// A directory whose name is not a valid glob pattern cannot be listed.
	badPattern := filepath.Join(t.TempDir(), "roles[")
	ok(t, os.Mkdir(badPattern, 0o755))
	// A directory named like a role file matches the glob but cannot be read.
	unreadable := t.TempDir()
	ok(t, os.Mkdir(filepath.Join(unreadable, "r.json"), 0o755))
	for name, path := range map[string]string{
		"missing": "testdata/nope", "empty directory": empty, "bad file": bad, "bad role file": badDir,
		"unreadable role file": unreadable, "bad pattern": badPattern,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadRolesFromPath(path); err == nil {
				t.Fatal("succeeded")
			}
		})
	}
}

func TestLoadRolesFromAPI(t *testing.T) {
	var views, sizes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		views = append(views, r.URL.Query().Get("view"))
		sizes = append(sizes, r.URL.Query().Get("pageSize"))
		page := map[string]any{"roles": []map[string]any{
			{
				"name":                "roles/b.one",
				"title":               "B One",
				"stage":               "GA",
				"includedPermissions": []string{"b.x.get"},
			},
		}, "nextPageToken": "next"}
		if r.URL.Query().Get("pageToken") == "next" {
			page = map[string]any{"roles": []map[string]any{
				{"name": "roles/b.two", "stage": "BETA", "deleted": true},
			}}
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer srv.Close()
	roles, err := LoadRolesFromAPI(
		context.Background(),
		option.WithEndpoint(srv.URL),
		option.WithoutAuthentication(),
	)
	ok(t, err)
	equals(t, roles, []Role{
		{
			Name:        "roles/b.one",
			Title:       "B One",
			Stage:       "GA",
			Permissions: []string{"b.x.get"},
		},
		{Name: "roles/b.two", Stage: "BETA", Deleted: true},
	})
	// spec: every page is requested with permissions included, and as
	// large as the API allows.
	equals(t, views, []string{"FULL", "FULL"})
	equals(t, sizes, []string{"1000", "1000"})

	failing := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(
				w,
				`{"error": {"code": 403, "message": "denied"}}`,
				http.StatusForbidden,
			)
		}),
	)
	defer failing.Close()
	if _, err := LoadRolesFromAPI(
		context.Background(),
		option.WithEndpoint(failing.URL),
		option.WithoutAuthentication(),
	); err == nil {
		t.Fatal("LoadRolesFromAPI succeeded against a failing server")
	}
	// Conflicting options make the client fail to build.
	if _, err := LoadRolesFromAPI(
		context.Background(),
		option.WithoutAuthentication(),
		option.WithAPIKey("k"),
	); err == nil {
		t.Fatal("LoadRolesFromAPI succeeded with conflicting options")
	}
	// A cancelled context stops the listing before any page is fetched.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	views = nil
	if _, err := LoadRolesFromAPI(
		cancelled,
		option.WithEndpoint(srv.URL),
		option.WithoutAuthentication(),
	); err == nil {
		t.Fatal("LoadRolesFromAPI succeeded with a cancelled context")
	}
	equals(t, len(views), 0)
}

func TestWritePredefinedRolesMatchesGolden(t *testing.T) {
	sel := SelectRoles(
		[]string{
			"datastore.entities.get",
			"datastore.entities.create",
			"storage.objects.get",
			"nope.x.y",
		},
		[]Role{
			{
				Name:  "roles/datastore.user",
				Title: "Cloud Datastore User",
				Stage: "GA",
				Permissions: []string{
					"datastore.entities.get",
					"datastore.entities.create",
					"datastore.entities.list",
				},
			},
			{
				Name:  "roles/storage.objectViewer",
				Title: "Storage Object Viewer",
				Stage: "GA",
				Permissions: []string{
					"storage.objects.get",
					"storage.objects.list",
				},
			},
		},
		RoleFilter{},
	)
	bins := []Binary{
		{Package: "example.com/one", PredefinedRoles: &sel},
		{Package: "example.com/none", PredefinedRoles: &RoleSelection{}},
		{Package: "example.com/unselected"},
		{Package: "example.com/greedy", PredefinedRoles: &RoleSelection{
			Grants: []RoleGrant{
				{
					Role:   "roles/big.admin",
					Title:  "Big Admin",
					Size:   9,
					Covers: []string{"big.a.get"},
				},
			},
			Inexact: true,
			Excess:  8,
		}},
	}
	var buf bytes.Buffer
	ok(t, WritePredefinedRoles(&buf, bins))
	want, err := os.ReadFile("testdata/golden/predefined.txt")
	ok(t, err)
	if buf.String() != string(want) {
		t.Fatalf(
			"output differs from predefined.txt:\n--- got\n%s\n--- want\n%s",
			buf.String(),
			want,
		)
	}
	w := &flakyWriter{n: 2}
	if err := WritePredefinedRoles(w, bins); err == nil {
		t.Fatal("write error not returned")
	}
}

// sized returns a role of the given total size granting the required
// permissions covers, by index, padded with permissions nothing requires.
func sized(name string, size int, covers ...int) (Role, bitset) {
	r := Role{Name: name, Stage: "GA"}
	set := newBitset(0)
	for _, j := range covers {
		r.Permissions = append(r.Permissions, "x.need.p"+strconv.Itoa(j))
		set.add(j)
	}
	for len(r.Permissions) < size {
		r.Permissions = append(r.Permissions, "x.pad.p"+strconv.Itoa(len(r.Permissions)))
	}
	return r, set
}

func TestExactCoverIsOptimal(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		k := rapid.IntRange(1, 6).Draw(t, "permissions")
		n := rapid.IntRange(1, 6).Draw(t, "roles")
		sets := make([]bitset, n)
		roles := make([]*Role, n)
		union := newBitset(k)
		for i := range n {
			covers := rapid.SliceOfNDistinct(rapid.IntRange(0, k-1), 1, k, rapid.ID[int]).
				Draw(t, "covers")
			extra := rapid.IntRange(0, 3).Draw(t, "extra")
			r, set := sized("roles/x.r"+strconv.Itoa(i), len(covers)+extra, covers...)
			roles[i], sets[i] = &r, set
			union.or(set)
		}
		perms := union.members()
		picks := exactCover(perms, sets, roles)

		var got cost
		covered := newBitset(k)
		for _, i := range picks {
			got.size += len(roles[i].Permissions)
			got.roles++
			covered.or(sets[i])
		}
		// spec: the picks cover every permission and cost exactly as little,
		// in permissions and then in roles, as the cheapest subset of roles
		// that covers them.
		equals(t, covered.intersectCount(union), len(perms))
		var want cost
		found := false
		for mask := 1; mask < 1<<n; mask++ {
			var c cost
			s := newBitset(k)
			for i := range n {
				if mask&(1<<i) != 0 {
					c.size += len(roles[i].Permissions)
					c.roles++
					s.or(sets[i])
				}
			}
			if s.intersectCount(union) == len(perms) && (!found || c.less(want)) {
				want, found = c, true
			}
		}
		equals(t, got, want)
		if !slices.IsSorted(picks) || len(slices.Compact(slices.Clone(picks))) != len(picks) {
			t.Fatalf("picks %v are not sorted and distinct", picks)
		}
	})
}

func TestCostLess(t *testing.T) {
	tests := map[string]struct {
		c, d cost
		want bool
	}{
		"fewer permissions":             {c: cost{3, 5}, d: cost{4, 1}, want: true},
		"more permissions":              {c: cost{4, 1}, d: cost{3, 5}},
		"same permissions, fewer roles": {c: cost{4, 1}, d: cost{4, 2}, want: true},
		"same permissions, more roles":  {c: cost{4, 2}, d: cost{4, 1}},
		"equal":                         {c: cost{4, 2}, d: cost{4, 2}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, tc.c.less(tc.d), tc.want)
		})
	}
}

func TestHeir(t *testing.T) {
	const p = "b.things.get"
	tests := map[string]struct {
		kept []Role
		want int
	}{
		"no role holds it": {
			kept: []Role{role("roles/a.x", "a.things.get")},
			want: -1,
		},
		"roles without it are skipped": {
			kept: []Role{role("roles/b.x", "b.other.get"), role("roles/b.y", p)},
			want: 1,
		},
		"the first holder stays when the next is worse": {
			kept: []Role{role("roles/b.own", p), role("roles/a.foreign", p)},
			want: 0,
		},
		"a later holder stays when the next is worse": {
			kept: []Role{
				role("roles/b.x", "b.other.get"),
				role("roles/b.own", p),
				role("roles/a.foreign", p),
			},
			want: 1,
		},
		"its own service beats a smaller foreign role": {
			kept: []Role{
				role("roles/a.foreign", p),
				role("roles/b.own", p, "b.x.get", "b.y.get"),
			},
			want: 1,
		},
		"the smaller of two own-service roles": {
			kept: []Role{role("roles/b.big", p, "b.x.get"), role("roles/b.small", p)},
			want: 1,
		},
		"the smaller of two foreign roles": {
			kept: []Role{role("roles/a.big", p, "a.x.get"), role("roles/c.small", p)},
			want: 1,
		},
		"the name breaks a size tie": {
			kept: []Role{role("roles/b.y", p), role("roles/b.x", p)},
			want: 1,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			kept := make([]candidate, len(tc.kept))
			for i := range tc.kept {
				kept[i] = candidate{role: &tc.kept[i]}
			}
			equals(t, heir(kept, p), tc.want)
		})
	}
}

func TestGreedyCover(t *testing.T) {
	type spec struct {
		size   int
		covers []int
	}
	tests := map[string]struct {
		roles []spec
		perms []int
		want  []int
	}{
		"fewest permissions per newly covered one, each round": {
			// r2 (1 per permission) first, then r1 (2 per permission)
			// over r0 (3 per permission) for what is left.
			roles: []spec{{3, []int{0}}, {4, []int{0, 1}}, {1, []int{2}}},
			perms: []int{0, 1, 2},
			want:  []int{1, 2},
		},
		"a worse ratio listed later loses": {
			roles: []spec{{6, []int{0, 1}}, {8, []int{0, 1}}},
			perms: []int{0, 1},
			want:  []int{0},
		},
		"a better ratio listed later wins": {
			roles: []spec{{8, []int{0, 1}}, {6, []int{0, 1}}},
			perms: []int{0, 1},
			want:  []int{1},
		},
		"an equal ratio goes to the role covering more": {
			roles: []spec{{2, []int{0}}, {4, []int{0, 1}}},
			perms: []int{0, 1},
			want:  []int{1},
		},
		"an equal ratio covering less does not replace the pick": {
			roles: []spec{{4, []int{0, 1}}, {2, []int{0}}},
			perms: []int{0, 1},
			want:  []int{0},
		},
		"a worse ratio covering more does not replace the pick": {
			roles: []spec{{1, []int{0}}, {4, []int{0, 1}}},
			perms: []int{0, 1},
			want:  []int{0, 1},
		},
		"a role covering nothing new is never picked": {
			roles: []spec{{1, []int{0}}, {1, []int{0}}, {5, []int{1}}},
			perms: []int{0, 1},
			want:  []int{0, 2},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sets := make([]bitset, len(tc.roles))
			roles := make([]*Role, len(tc.roles))
			for i, s := range tc.roles {
				r, set := sized("roles/x.r"+strconv.Itoa(i), s.size, s.covers...)
				roles[i], sets[i] = &r, set
			}
			equals(t, greedyCover(tc.perms, sets, roles), tc.want)
		})
	}
}

func TestSelectRolesExactUpToMaxExact(t *testing.T) {
	// The literal sizes pin maxExact itself: 20 permissions in one group are
	// solved exactly, 21 greedily.
	for n, wantInexact := range map[int]bool{20: false, 21: true} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			var need []string
			roles := []Role{role("roles/big.admin")}
			for i := range n {
				p := "big.things.p" + strconv.Itoa(i)
				need = append(need, p)
				roles = append(roles, role("roles/big.r"+strconv.Itoa(i), p))
				roles[0].Permissions = append(roles[0].Permissions, p)
			}
			sel := SelectRoles(need, roles, RoleFilter{})
			equals(t, sel.Inexact, wantInexact)
			equals(t, grantNames(sel), []string{"roles/big.admin"})
		})
	}
}

func TestSelectRolesInexactWhenAnyGroupIs(t *testing.T) {
	// One group too large to solve exactly, between two that are not:
	// whichever order the groups are solved in, one solved exactly comes
	// after the greedy one.
	need := []string{"a.solo.get", "z.solo.get"}
	roles := []Role{
		role("roles/a.solo", "a.solo.get"),
		role("roles/z.solo", "z.solo.get"),
		role("roles/m.admin"),
	}
	for i := range maxExact + 1 {
		p := "m.things.p" + strconv.Itoa(i)
		need = append(need, p)
		roles = append(roles, role("roles/m.r"+strconv.Itoa(i), p))
		roles[2].Permissions = append(roles[2].Permissions, p)
	}
	sel := SelectRoles(need, roles, RoleFilter{})
	equals(t, sel.Inexact, true)
	equals(t, grantNames(sel), []string{"roles/a.solo", "roles/m.admin", "roles/z.solo"})
}

func TestSelectRolesBreaksTiesByName(t *testing.T) {
	// Two equally cheap roles, listed out of order: the choice must not
	// depend on that order.
	roles := []Role{role("roles/x.b", "x.things.get"), role("roles/x.a", "x.things.get")}
	equals(t, grantNames(SelectRoles([]string{"x.things.get"}, roles, RoleFilter{})),
		[]string{"roles/x.a"})
}

func TestSelectRolesSortsGrantsByName(t *testing.T) {
	// Pruning visits larger roles first, so a larger role named later must
	// still be listed after a smaller one named earlier.
	roles := []Role{
		role("roles/a.small", "a.things.get"),
		role("roles/b.big", "b.things.get", "b.x.get", "b.y.get"),
	}
	sel := SelectRoles([]string{"b.things.get", "a.things.get"}, roles, RoleFilter{})
	equals(t, grantNames(sel), []string{"roles/a.small", "roles/b.big"})
}

func TestBitsetAcrossWords(t *testing.T) {
	// Sized for n bits: one word per 64, rounded up.
	for n, words := range map[int]int{0: 0, 1: 1, 64: 1, 65: 2, 128: 2, 129: 3} {
		equals(t, len(newBitset(n)), words)
	}

	b := newBitset(0)
	b.add(0)
	equals(t, len(b), 1) // adding a bit grows only to the word it is in
	b.add(63)
	b.add(64)
	b.add(127)
	equals(t, len(b), 2)
	equals(t, b.members(), []int{0, 63, 64, 127})
	for i, want := range map[int]bool{62: false, 63: true, 64: true, 65: false, 127: true, 128: false, 1000: false} {
		equals(t, b.has(i), want)
	}

	// or grows the receiver to the longer set and keeps its own bits.
	short := newBitset(0)
	short.add(1)
	short.or(b)
	equals(t, short.members(), []int{0, 1, 63, 64, 127})
	empty := newBitset(0)
	empty.or(b)
	equals(t, empty.members(), b.members())

	// Intersections count every word, and a shorter argument is fine.
	c := newBitset(0)
	c.add(63)
	c.add(64)
	equals(t, b.intersectCount(c), 2)
	one := newBitset(0)
	one.add(0)
	equals(t, b.intersectCount(one), 1)

	// A bit in the second word alone is found there, not in the first.
	high := newBitset(0)
	high.add(64)
	equals(t, high.has(64), true)
	equals(t, high.has(0), false)
	grown := newBitset(0)
	grown.or(high)
	equals(t, grown.members(), []int{64})

	// andNot with a shorter argument leaves the words past it alone.
	b.andNot(one)
	equals(t, b.members(), []int{63, 64, 127})
}

func TestExactCoverPrefersFewerRolesAtEqualSize(t *testing.T) {
	// r1+r5 and r0+r2+r4 both grant 8 permissions. The search reaches the
	// three-role cover first, so only the role count makes it prefer r1+r5.
	specs := []struct {
		size   int
		covers []int
	}{
		{1, []int{0}},
		{4, []int{0, 1, 2}},
		{2, []int{1}},
		{1, []int{0}},
		{5, []int{2, 3}},
		{4, []int{3}},
	}
	sets := make([]bitset, len(specs))
	roles := make([]*Role, len(specs))
	for i, s := range specs {
		r, set := sized("roles/x.r"+strconv.Itoa(i), s.size, s.covers...)
		roles[i], sets[i] = &r, set
	}
	equals(t, exactCover([]int{0, 1, 2, 3}, sets, roles), []int{1, 5})
}

func TestSelectRolesSolvesManySmallGroupsExactly(t *testing.T) {
	// More unrelated permissions than maxExact: each is its own group, so
	// every group is solved exactly.
	var need []string
	var roles []Role
	for i := range maxExact + 5 {
		p := "x.things.p" + strconv.Itoa(i)
		need = append(need, p)
		roles = append(roles,
			role("roles/x.small"+strconv.Itoa(i), p),
			role("roles/x.big"+strconv.Itoa(i), p, "x.extra.p"+strconv.Itoa(i)))
	}
	sel := SelectRoles(need, roles, RoleFilter{})
	equals(t, sel.Inexact, false)
	equals(t, len(sel.Grants), maxExact+5)
	equals(t, sel.Excess, 0)
}

func TestSelectRolesKeepsTheHeirOfAPrunedRole(t *testing.T) {
	// b.r0 makes a.r3 redundant and inherits a.x.list from it. a.r4 holds
	// b.x.get, which b.r0 was chosen for, but not a.x.list, so b.r0 must
	// stay: pruning it too would leave a.x.list ungranted.
	roles := []Role{
		role("roles/b.r0", "a.x.list", "b.x.get"),
		role("roles/a.r1", "a.x.get"),
		role("roles/a.r3", "a.x.get", "a.x.list"),
		role("roles/a.r4", "a.y.get", "b.x.get"),
	}
	sel := SelectRoles([]string{"a.x.list", "a.y.get", "b.x.get"}, roles, RoleFilter{})
	equals(t, sel.Uncovered, []string(nil))
	covered := make(map[string]bool)
	for _, g := range sel.Grants {
		for _, p := range g.Covers {
			covered[p] = true
		}
	}
	equals(t, covered, map[string]bool{"a.x.list": true, "a.y.get": true, "b.x.get": true})
}
