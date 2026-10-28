package gcpperms

import (
	"cmp"
	"context"
	"encoding/json"
	"maps"
	"math/bits"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// maxExact is the largest number of permissions in one connected group
// that SelectRoles solves exactly; the search is exponential in it.
const maxExact = 20

// Role is a predefined (built-in) IAM role.
type Role struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Stage       string   `json:"stage"`
	Deleted     bool     `json:"deleted,omitempty"`
	Permissions []string `json:"includedPermissions"`
}

// RoleFilter decides which predefined roles may be recommended.
type RoleFilter struct {
	// Stages are the launch stages allowed, such as GA and BETA. Empty
	// means GA only: pre-GA roles change without notice, and many are
	// meant for one special principal, such as BigQuery's authorized
	// routine roles.
	Stages []string
}

// RoleGrant is one recommended role and what it is recommended for.
type RoleGrant struct {
	Role  string `json:"role"`
	Title string `json:"title,omitempty"`
	Stage string `json:"stage,omitempty"`
	// Size is the number of permissions the role grants.
	Size int `json:"size"`
	// Covers are the required permissions the role was chosen to grant.
	// A role chosen for its own service's permissions may also hold
	// another service's; those are attributed to that service's role,
	// unless that role was pruned as redundant.
	Covers []string `json:"covers"`
}

// RoleSelection is a set of predefined roles granting a set of permissions.
type RoleSelection struct {
	Grants []RoleGrant `json:"grants"`
	// Excess is the number of permissions the roles grant beyond those
	// required.
	Excess int `json:"excess"`
	// Uncovered are required permissions no allowed predefined role grants;
	// they need a custom role.
	Uncovered []string `json:"uncovered,omitempty"`
	// Inexact is set when part of the problem was too large to solve
	// exactly and a greedy choice was made instead.
	Inexact bool `json:"inexact,omitempty"`
}

// candidate is an allowed role granting a required permission, with the
// bit set of required permissions it is chosen to grant.
type candidate struct {
	role *Role
	set  bitset
}

// component is a group of required permissions that no candidate links
// to any other, with the candidates granting them.
type component struct {
	perms []int
	cands []candidate
}

// cost orders choices of roles: total permissions granted, then the number
// of roles.
type cost struct{ size, roles int }

// bitset is a set of small non-negative integers.
type bitset []uint64

// unionFind is a disjoint-set forest over 0..n-1.
type unionFind []int

// LoadRolesFromAPI lists every predefined role, with its permissions, from
// the IAM API. It needs credentials (Application Default Credentials by
// default) but no IAM permission: any authenticated principal can list
// predefined roles.
func LoadRolesFromAPI(ctx context.Context, opts ...option.ClientOption) ([]Role, error) {
	const op = "gcpperms.LoadRolesFromAPI"
	svc, err := iam.NewService(ctx, opts...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	var roles []Role
	// The FULL view includes each role's permissions.
	err = svc.Roles.List().
		View("FULL").
		PageSize(1000).
		Pages(ctx, func(page *iam.ListRolesResponse) error {
			for _, r := range page.Roles {
				roles = append(roles, Role{
					Name:        r.Name,
					Title:       r.Title,
					Stage:       r.Stage,
					Deleted:     r.Deleted,
					Permissions: r.IncludedPermissions,
				})
			}
			return nil
		})
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return roles, nil
}

// LoadRolesFromPath reads predefined roles saved as JSON: a directory of
// one role per file, as `gcloud iam roles describe --format=json` writes
// them (iam-dataset's gcp/roles), or a file holding a JSON array of roles.
func LoadRolesFromPath(path string) ([]Role, error) {
	const op = "gcpperms.LoadRolesFromPath"
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	if !info.IsDir() {
		var roles []Role
		if err := readJSONFile(path, &roles); err != nil {
			return nil, errors.Wrap(err, op)
		}
		return roles, nil
	}
	files, err := filepath.Glob(filepath.Join(path, "*.json"))
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	if len(files) == 0 {
		return nil, errors.Errorf("%s: no role files in %s", op, path)
	}
	roles := make([]Role, 0, len(files))
	for _, f := range files {
		var r Role
		if err := readJSONFile(f, &r); err != nil {
			return nil, errors.Wrap(err, op)
		}
		roles = append(roles, r)
	}
	return roles, nil
}

func readJSONFile(file string, v any) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return errors.Wrap(err, "reading role data")
	}
	return errors.Wrapf(json.Unmarshal(data, v), "parsing %s", file)
}

// spansAllServices reports whether name is a role of no one service, such
// as the basic roles (roles/owner, editor, viewer, browser) and roles/admin,
// writer, and reader. Each grants broad access across every service, the
// opposite of least privilege; their names have no service part.
func spansAllServices(name string) bool {
	return !strings.Contains(strings.TrimPrefix(name, "roles/"), ".")
}

// allows reports whether r may be recommended. Never recommended are custom
// roles, which belong to one project or organization; roles spanning all
// services, such as the basic roles; service agent and system roles, which
// Google grants to its own service accounts; and legacy roles, kept for
// compatibility with ACLs.
func (f RoleFilter) allows(r *Role) bool {
	_, short, _ := strings.Cut(r.Name, ".")
	switch {
	case !strings.HasPrefix(r.Name, "roles/"):
		return false
	case r.Deleted, spansAllServices(r.Name), r.Stage == "DEPRECATED":
		return false
	case strings.HasSuffix(strings.ToLower(r.Name), "serviceagent") || strings.Contains(r.Title, "Service Agent"):
		return false
	case strings.HasPrefix(short, "legacy") || short == "system" || strings.HasSuffix(short, ".system"):
		return false
	case len(f.Stages) > 0:
		return slices.Contains(f.Stages, r.Stage)
	default:
		return r.Stage == "GA"
	}
}

// roleService is the service a role belongs to: datastore for
// roles/datastore.user.
func roleService(name string) string {
	svc, _, _ := strings.Cut(strings.TrimPrefix(name, "roles/"), ".")
	return svc
}

// SelectRoles chooses predefined roles that together grant every required
// permission while granting as few permissions as possible.
//
// A permission is granted only through roles of its own service (a
// datastore.* permission through roles/datastore.* roles) when any such
// role grants it. The smallest role holding a permission often belongs to
// another product, such as a Firebase or Storage Transfer role that happens
// to include Datastore or Pub/Sub permissions; granting it would be
// surprising to review and would change with that product's needs.
//
// Among those roles it minimizes the total size of the chosen roles, then
// the number of roles. It then prunes any chosen role whose permissions
// the others already grant: the same-service rule decides which role a
// permission is chosen through, but never adds a role that grants nothing
// new. Groups of permissions that no candidate role links
// are solved independently, which keeps each search small. A group of more
// than maxExact permissions is solved greedily instead.
func SelectRoles(required []string, roles []Role, filter RoleFilter) RoleSelection {
	need := slices.Compact(slices.Sorted(slices.Values(required)))
	index := make(map[string]int, len(need))
	for i, p := range need {
		index[p] = i
	}
	cands := candidates(len(need), index, allowedRoles(roles, filter))

	var sel RoleSelection
	covered := newBitset(len(need))
	for _, c := range cands {
		covered.or(c.set)
	}
	for i, p := range need {
		if !covered.has(i) {
			sel.Uncovered = append(sel.Uncovered, p)
		}
	}

	var chosen []candidate
	for _, comp := range components(len(need), cands, covered) {
		picks, exact := cover(comp)
		chosen = append(chosen, picks...)
		sel.Inexact = sel.Inexact || !exact
	}
	chosen = pruneRedundant(chosen, need)
	sel.Grants, sel.Excess = grants(chosen, need, index)
	return sel
}

// allowedRoles returns the roles filter allows.
func allowedRoles(roles []Role, filter RoleFilter) []*Role {
	allowed := make([]*Role, 0, len(roles))
	for i := range roles {
		if filter.allows(&roles[i]) {
			allowed = append(allowed, &roles[i])
		}
	}
	return allowed
}

// candidates returns the allowed roles that grant a required permission,
// each with the set of required permissions it may be chosen for under the
// same-service rule. index numbers the n required permissions. Smaller
// roles come first, then by name, so ties resolve the same way whatever
// order the roles were listed in.
func candidates(n int, index map[string]int, allowed []*Role) []candidate {
	home := homeGranted(n, index, allowed)
	var cands []candidate
	for _, r := range allowed {
		set := newBitset(n)
		for _, p := range r.Permissions {
			j, ok := index[p]
			if ok && (!home.has(j) || roleService(r.Name) == serviceOf(p)) {
				set.add(j)
			}
		}
		if !set.empty() {
			cands = append(cands, candidate{role: r, set: set})
		}
	}
	slices.SortFunc(cands, func(a, b candidate) int {
		return cmp.Or(
			cmp.Compare(len(a.role.Permissions), len(b.role.Permissions)),
			strings.Compare(a.role.Name, b.role.Name),
		)
	})
	return cands
}

// homeGranted returns the set of required permissions, numbered by index,
// that a role of the permission's own service grants.
func homeGranted(n int, index map[string]int, allowed []*Role) bitset {
	home := newBitset(n)
	for _, r := range allowed {
		for _, p := range r.Permissions {
			if j, ok := index[p]; ok && roleService(r.Name) == serviceOf(p) {
				home.add(j)
			}
		}
	}
	return home
}

// components groups the covered permissions of n required ones: two
// permissions are connected when some candidate grants both. Each group
// comes with its candidates, in their order in cands, and groups are
// ordered by their root so the result is deterministic.
func components(n int, cands []candidate, covered bitset) []component {
	uf := newUnionFind(n)
	for _, c := range cands {
		members := c.set.members()
		for _, j := range members[1:] {
			uf.union(members[0], j)
		}
	}
	groups := make(map[int]*component)
	for i := range n {
		if covered.has(i) {
			root := uf.find(i)
			if groups[root] == nil {
				groups[root] = &component{}
			}
			groups[root].perms = append(groups[root].perms, i)
		}
	}
	for _, c := range cands {
		g := groups[uf.find(c.set.members()[0])]
		g.cands = append(g.cands, c)
	}
	out := make([]component, 0, len(groups))
	for _, root := range slices.Sorted(maps.Keys(groups)) {
		out = append(out, *groups[root])
	}
	return out
}

// cover chooses the cheapest candidates covering comp, exactly when it has
// at most maxExact permissions and greedily otherwise. It reports whether
// the choice was exact.
func cover(comp component) (picks []candidate, exact bool) {
	sets := make([]bitset, len(comp.cands))
	roles := make([]*Role, len(comp.cands))
	for i, c := range comp.cands {
		sets[i], roles[i] = c.set, c.role
	}
	exact = len(comp.perms) <= maxExact
	var idx []int
	if exact {
		idx = exactCover(comp.perms, sets, roles)
	} else {
		idx = greedyCover(comp.perms, sets, roles)
	}
	for _, i := range idx {
		picks = append(picks, comp.cands[i])
	}
	return picks, exact
}

// grants describes the chosen roles, sorted by name, and counts the
// permissions they grant beyond the required ones, which index numbers.
func grants(chosen []candidate, need []string, index map[string]int) ([]RoleGrant, int) {
	granted := make(map[string]bool)
	out := make([]RoleGrant, 0, len(chosen))
	for _, c := range chosen {
		r := c.role
		g := RoleGrant{
			Role:  r.Name,
			Title: r.Title,
			Stage: r.Stage,
			Size:  len(r.Permissions),
		}
		for _, p := range r.Permissions {
			granted[p] = true
		}
		for _, j := range c.set.members() {
			g.Covers = append(g.Covers, need[j])
		}
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b RoleGrant) int { return strings.Compare(a.Role, b.Role) })
	excess := 0
	for p := range granted {
		if _, ok := index[p]; !ok {
			excess++
		}
	}
	return out, excess
}

// pruneRedundant drops each chosen role whose required permissions the
// other chosen roles already grant. That happens when a role chosen for its
// own service also holds another service's permission, so the role chosen
// for that service adds nothing, or when one chosen role holds every
// permission of another. Larger roles are tried first, so the most
// permissions are shed. A dropped role's permissions pass at once to a
// remaining role that holds them, so a later check of that role counts
// them: it stays unless the others also grant what it inherited.
func pruneRedundant(chosen []candidate, need []string) []candidate {
	kept := slices.Clone(chosen)
	for i := range kept {
		kept[i].set = slices.Clone(kept[i].set)
	}
	slices.SortFunc(kept, func(a, b candidate) int {
		return cmp.Or(
			cmp.Compare(len(b.role.Permissions), len(a.role.Permissions)),
			strings.Compare(a.role.Name, b.role.Name),
		)
	})
	for i := 0; i < len(kept); {
		others := slices.Concat(kept[:i], kept[i+1:])
		redundant := true
		for _, j := range kept[i].set.members() {
			redundant = redundant &&
				slices.ContainsFunc(others, func(o candidate) bool {
					return slices.Contains(o.role.Permissions, need[j])
				})
		}
		if !redundant {
			i++
			continue
		}
		// Redundant, so some other role holds each of its permissions.
		for _, j := range kept[i].set.members() {
			others[heir(others, need[j])].set.add(j)
		}
		kept = others
	}
	return kept
}

// heir is the index of the kept role a dropped role's permission p is
// attributed to: a role holding p, preferring p's own service, then the
// smaller role, then the name.
func heir(kept []candidate, p string) int {
	best := -1
	for i, c := range kept {
		if !slices.Contains(c.role.Permissions, p) {
			continue
		}
		if best < 0 {
			best = i
			continue
		}
		b := kept[best].role
		if cmp.Or(
			-cmp.Compare(
				boolInt(roleService(c.role.Name) == serviceOf(p)),
				boolInt(roleService(b.Name) == serviceOf(p)),
			),
			cmp.Compare(len(c.role.Permissions), len(b.Permissions)),
			strings.Compare(c.role.Name, b.Name),
		) < 0 {
			best = i
		}
	}
	return best
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (c cost) less(d cost) bool {
	return c.size < d.size || c.size == d.size && c.roles < d.roles
}

// exactCover returns the indexes of the cheapest roles covering perms, by
// dynamic programming over subsets of perms. sets[i] is the set of required
// permissions roles[i] grants; roles are ordered by preference for ties.
func exactCover(perms []int, sets []bitset, roles []*Role) []int {
	masks := subsetMasks(perms, sets)
	full := uint32(1)<<len(perms) - 1
	const unreached = -1
	best := make([]cost, full+1)
	from := make([]int, full+1) // role that reached each subset
	prev := make([]uint32, full+1)
	for m := range best {
		from[m] = unreached
	}
	from[0] = len(sets) // the empty set is reached by choosing nothing
	for m := uint32(0); m < full; m++ {
		if from[m] == unreached {
			continue
		}
		for i, rm := range masks {
			next := m | rm
			c := cost{best[m].size + len(roles[i].Permissions), best[m].roles + 1}
			if next != m && (from[next] == unreached || c.less(best[next])) {
				best[next], from[next], prev[next] = c, i, m
			}
		}
	}
	var picks []int
	for m := full; m != 0; m = prev[m] {
		picks = append(picks, from[m])
	}
	slices.Sort(picks)
	return picks
}

// subsetMasks renumbers the group's permissions 0..k-1 and returns each
// role's set of them as a bit mask, to index subsets.
func subsetMasks(perms []int, sets []bitset) []uint32 {
	local := make(map[int]uint, len(perms))
	for i, p := range perms {
		local[p] = uint(i)
	}
	masks := make([]uint32, len(sets))
	for i, s := range sets {
		for _, p := range s.members() {
			masks[i] |= 1 << local[p]
		}
	}
	return masks
}

// greedyCover repeatedly picks the role granting the fewest permissions per
// newly covered required permission, preferring the role that covers more
// on a tie.
func greedyCover(perms []int, sets []bitset, roles []*Role) []int {
	left := newBitset(0)
	for _, p := range perms {
		left.add(p)
	}
	var picks []int
	for !left.empty() {
		pick, pickNew := -1, 0
		for i, s := range sets {
			n := s.intersectCount(left)
			if n == 0 {
				continue
			}
			// Compare size/n ratios without division.
			if pick < 0 {
				pick, pickNew = i, n
				continue
			}
			mine, theirs := len(
				roles[i].Permissions,
			)*pickNew, len(
				roles[pick].Permissions,
			)*n
			if mine < theirs || mine == theirs && n > pickNew {
				pick, pickNew = i, n
			}
		}
		picks = append(picks, pick)
		left.andNot(sets[pick])
	}
	slices.Sort(picks)
	return picks
}

func newBitset(n int) bitset { return make(bitset, (n+63)/64) }

func (b *bitset) add(i int) {
	for len(*b) <= i/64 {
		*b = append(*b, 0)
	}
	(*b)[i/64] |= 1 << (i % 64)
}

func (b bitset) has(i int) bool { return i/64 < len(b) && b[i/64]&(1<<(i%64)) != 0 }

func (b bitset) empty() bool {
	for _, w := range b {
		if w != 0 {
			return false
		}
	}
	return true
}

func (b *bitset) or(c bitset) {
	for i, w := range c {
		if i >= len(*b) {
			*b = append(*b, 0)
		}
		(*b)[i] |= w
	}
}

func (b bitset) andNot(c bitset) {
	for i := range b {
		if i < len(c) {
			b[i] &^= c[i]
		}
	}
}

func (b bitset) intersectCount(c bitset) int {
	n := 0
	for i := range b {
		if i < len(c) {
			n += bits.OnesCount64(b[i] & c[i])
		}
	}
	return n
}

func (b bitset) members() []int {
	var out []int
	for i, w := range b {
		for w != 0 {
			j := bits.TrailingZeros64(w)
			out = append(out, i*64+j)
			w &^= 1 << j
		}
	}
	return out
}

func newUnionFind(n int) unionFind {
	uf := make(unionFind, n)
	for i := range uf {
		uf[i] = i
	}
	return uf
}

func (uf unionFind) find(i int) int {
	for uf[i] != i {
		uf[i] = uf[uf[i]]
		i = uf[i]
	}
	return i
}

func (uf unionFind) union(a, b int) { uf[uf.find(a)] = uf.find(b) }

// serviceOf is the service a permission belongs to: datastore for
// datastore.entities.get.
func serviceOf(perm string) string {
	svc, _, _ := strings.Cut(perm, ".")
	return svc
}
