package verifytable

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// metricWriterReason accepts the metric exporter's permissions: Monitoring's
// method pages name none, and its access-control page lists permissions by
// role only.
const metricWriterReason = "Monitoring documents no permission per method; the permission is in " +
	"roles/monitoring.metricWriter, which " +
	"https://docs.cloud.google.com/stackdriver/docs/instrumentation/setup/go tells you to grant"

const (
	// Confirmed means the documentation states what the rule grants.
	Confirmed Status = iota
	// Mismatch means the documentation requires a permission the rule
	// lacks, or names none of a permission the rule grants.
	Mismatch
	// Unverified means no traced RPC is documented.
	Unverified
	// NotIAM means the rule grants nothing and notes a non-IAM requirement.
	NotIAM
	// Accepted means the only differences are permissions acceptedReasons
	// lists.
	Accepted
)

// nameFinding is a table permission the IAM reference does not list as is.
type nameFinding struct {
	Permission string
	// Canonical is the reference's spelling when only the case differs;
	// empty when the permission is not listed at all.
	Canonical string
	Lines     []int
}

// entry is an SDK entry point the workspace calls, with its table rule,
// the RPCs it sends, and the SDK types it takes and returns.
type entry struct {
	api  string
	rule tableRule
	rpcs []RPC
	// recv, in, and out are the SDK types of the receiver, the receiver
	// and parameters, and the results.
	recv, in, out map[string]bool
}

// Status classifies a finding.
type Status int

// finding is the verdict on one entry point.
type finding struct {
	api     string
	status  Status
	missing []string // required by the docs, not granted
	extra   []string // granted, not named by the docs
	// accepted are extra permissions excused by acceptedReasons, with the
	// reason for each.
	accepted []string
	// granted are the permissions the rule grants, own and paid for.
	granted []string
	// methods are the REST methods of the RPCs checked, where known.
	methods []string
	// deferred is set when the RPCs checked belong to related calls.
	deferred bool
	detail   string
}

// basis is what an entry's rule is checked against: the entries whose
// RPCs are documented, how they relate to the rule, and the permissions
// the rule is credited with.
type basis struct {
	entries  []*entry
	how      string
	granted  []string
	deferred bool
}

// docSummary is what the documentation says about a basis's RPCs.
type docSummary struct {
	required, mentioned []string
	// sources name each documented RPC and where its permissions came
	// from; notes say why the others are undocumented.
	sources, notes []string
	methods        []string
}

// explainedRPC returns why an RPC the trace reaches from the entry point
// api is not a requirement, for RPCs that are not.
func explainedRPC(api, rpc string) (string, bool) {
	if rpc == "storage/v1.BucketsGetCall" &&
		api != "cloud.google.com/go/storage.BucketHandle.Attrs" {
		// Attrs sends this request itself; every other call only might.
		return "storage fetches bucket metadata in the background only when " +
			"GO_STORAGE_DEV_OTEL_TRACING=true, to label trace spans, and ignores failures " +
			"(storage@v1.69.0 trace.go startSpanWithBucket)", true
	}
	return "", false
}

// acceptedReasons returns the permissions a rule grants that the method
// documentation does not name, kept deliberately, keyed by entry point and
// permission, each with the reason.
func acceptedReasons() map[string]map[string]string {
	return map[string]map[string]string{
		"cloud.google.com/go/alloydbconn.Dialer.Dial": {
			"alloydb.clusters.generateclientcertificate": "the dialer calls GenerateClientCertificate, which is in no " +
				"public discovery document; the permission is in roles/alloydb.client, which AlloyDB's connector docs require",
			"alloydb.instances.get": "kept by the table's owner; it is in roles/alloydb.client, " +
				"which AlloyDB's connector docs require",
			"serviceusage.services.use": "AlloyDB's connector docs require roles/serviceusage.serviceUsageConsumer",
		},
		"github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric.New": {
			"monitoring.timeseries.create":        metricWriterReason,
			"monitoring.metricdescriptors.create": metricWriterReason,
		},
		"cloud.google.com/go/profiler.Start": {
			"cloudprofiler.profiles.update": "the agent uploads each profile with UpdateProfile, whose reference " +
				"page names no permission; the permission is in roles/cloudprofiler.agent, which " +
				"https://docs.cloud.google.com/profiler/docs/profiling-go tells you to grant",
		},
		"cloud.google.com/go/pubsub/v2/apiv1.TopicAdminClient.ListTopicSubscriptions": {
			"pubsub.topics.get": "Google documents no permission for projects.topics.subscriptions.list; unconfirmed",
		},
	}
}

// lowerSet returns the lowercased union of ss. IAM permission names are
// compared case-insensitively: REST reference pages sometimes spell them
// differently from the roles reference (dockerImages, dockerimages).
func lowerSet(ss ...[]string) map[string]bool {
	m := make(map[string]bool)
	for _, s := range ss {
		for _, x := range s {
			m[strings.ToLower(x)] = true
		}
	}
	return m
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkNames compares every permission the rules grant with known, the
// reference's permissions keyed by their lowercased name. It returns the
// findings sorted by permission and the number of distinct permissions.
func checkNames(rules []tableRule, known map[string]string) (findings []nameFinding, total int) {
	lines := make(map[string][]int)
	for _, r := range rules {
		for _, p := range slices.Concat(r.Perms, r.Maybe) {
			lines[p] = append(lines[p], r.Line)
		}
	}
	for _, p := range slices.Sorted(maps.Keys(lines)) {
		canonical, ok := known[strings.ToLower(p)]
		switch {
		case !ok:
			findings = append(findings, nameFinding{Permission: p, Lines: lines[p]})
		case canonical != p:
			findings = append(
				findings,
				nameFinding{Permission: p, Canonical: canonical, Lines: lines[p]},
			)
		}
	}
	return findings, len(lines)
}

// prefixes returns the sorted service prefixes of the permissions rules grant.
func prefixes(rules []tableRule) []string {
	set := make(map[string]bool)
	for _, r := range rules {
		for _, p := range slices.Concat(r.Perms, r.Maybe) {
			set[strings.Split(p, ".")[0]] = true
		}
	}
	return keys(set)
}

// newEntry builds an entry, dropping RPCs that explainedRPC excuses: an
// entry whose only RPCs are explained sends nothing that needs a permission.
func newEntry(api string, rule *tableRule, rpcs []RPC, recv, in, out map[string]bool) *entry {
	e := &entry{api: api, rule: *rule, recv: recv, in: in, out: out}
	for _, rpc := range rpcs {
		if _, explained := explainedRPC(api, rpc.String()); !explained {
			e.rpcs = append(e.rpcs, rpc)
		}
	}
	return e
}

func shares(a, b map[string]bool) bool {
	for t := range a {
		if b[t] {
			return true
		}
	}
	return false
}

// evaluate checks each entry's rule against the documentation of the RPCs
// it, or a related entry, sends. document returns what the docs say an RPC
// requires.
//
// The table charges some permissions to the call that creates an iterator,
// writer, or mutation rather than to the call that sends the request. Such
// calls are paired through the SDK types they share: a rule that grants
// permissions but sends no RPC is checked against the RPCs of entries that
// take its results or its receiver, and a no-permission rule that sends RPCs
// is checked against the permissions of the entries that produce its inputs.
func evaluate(es []*entry, document func(*RPC) (methodDoc, error)) []finding {
	var out []finding
	for _, e := range es {
		out = append(out, evaluateOne(e, es, document))
	}
	return slices.DeleteFunc(out, func(f finding) bool { return f.api == "" })
}

// evaluateOne checks one entry's rule; it returns a finding with no api
// when there is nothing to check.
func evaluateOne(e *entry, es []*entry, document func(*RPC) (methodDoc, error)) finding {
	r := e.rule
	b, done := chooseBasis(e, es)
	if done != nil {
		return *done
	}
	if len(b.entries) == 0 {
		return finding{api: e.api, status: Unverified, detail: fmt.Sprintf(
			"rule `%s` (line %d) grants %v but no RPC was traced, here or in a related call",
			r.Pattern,
			r.Line,
			b.granted,
		)}
	}
	how := b.how
	var related []string
	for _, c := range b.entries {
		if c != e {
			related = append(related, c.api)
		}
	}
	if len(related) > 0 {
		how += " " + strings.Join(related, ", ")
	}

	d := documentAll(b.entries, document)
	f := finding{api: e.api, granted: b.granted, methods: d.methods, deferred: b.deferred}
	ruleAll, docReq, docAll := lowerSet(
		b.granted,
	), lowerSet(
		d.required,
	), lowerSet(
		d.required,
		d.mentioned,
	)
	// A deferred rule is checked only for permissions no related RPC needs:
	// the related calls' own requirements belong to their rules.
	if !b.deferred {
		for _, p := range keys(docReq) {
			if !ruleAll[p] {
				f.missing = append(f.missing, p)
			}
		}
	}
	f.extra, f.accepted = extraPermissions(e, docAll)
	f.detail = fmt.Sprintf(
		"rule `%s` (line %d) grants %v; checked against %s; docs require %v, mention %v",
		r.Pattern,
		r.Line,
		keys(ruleAll),
		how,
		keys(docReq),
		keys(docAll),
	)
	for _, s := range slices.Concat(d.sources, d.notes) {
		f.detail += "\n    " + s
	}
	f.status = verdict(&f, len(d.sources))
	return f
}

// chooseBasis decides what e's rule is checked against. When the rule
// needs no check against RPCs, it returns the finding instead: NotIAM, or
// one with no api when there is nothing to check.
func chooseBasis(e *entry, es []*entry) (basis, *finding) {
	r := e.rule
	granted := slices.Concat(r.Perms, r.Maybe)
	switch {
	case len(granted) == 0 && r.Note != "":
		return basis{}, &finding{
			api:    e.api,
			status: NotIAM,
			detail: fmt.Sprintf("rule `%s` (line %d): %s", r.Pattern, r.Line, r.Note),
		}
	case len(granted) > 0 && len(e.rpcs) > 0:
		return basis{entries: []*entry{e}, how: "its own RPCs", granted: granted}, nil
	case len(granted) > 0:
		return basis{
			entries:  laterCalls(e, es),
			how:      "RPCs sent later by",
			granted:  granted,
			deferred: true,
		}, nil
	case len(e.rpcs) > 0:
		// A no-permission rule whose RPCs another call's rule pays for.
		producers, paid := payers(e, es)
		return basis{
			entries: []*entry{e},
			how:     "its own RPCs, paid for by " + strings.Join(producers, ", "),
			granted: slices.Concat(granted, paid),
		}, nil
	default:
		return basis{}, &finding{} // no permissions, no RPCs: nothing to check
	}
}

// payers returns the entries whose rules pay for the RPCs of e, a
// no-permission rule, and the permissions they grant: the calls that
// produce e's inputs, as results or, when they send nothing themselves, as
// receivers.
func payers(e *entry, es []*entry) (apis, granted []string) {
	for _, c := range es {
		if c != e && !c.rule.noop() &&
			(shares(c.out, e.in) || shares(c.recv, e.in) && len(c.rpcs) == 0) {
			apis = append(apis, c.api)
			granted = slices.Concat(granted, c.rule.Perms, c.rule.Maybe)
		}
	}
	return apis, granted
}

// laterCalls returns the entries that send the RPCs e's permissions are
// charged for: the calls that take e's results (an iterator's Next, a
// writer's Close), or else the calls that take e's receiver (a
// transaction's Commit, or RunInTransaction, which commits it).
func laterCalls(e *entry, es []*entry) []*entry {
	var out []*entry
	for _, c := range es {
		if c != e && len(c.rpcs) > 0 && shares(e.out, c.in) {
			out = append(out, c)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, c := range es {
		if c != e && len(c.rpcs) > 0 && shares(e.recv, c.in) {
			out = append(out, c)
		}
	}
	return out
}

// documentAll looks up the documentation of every RPC the entries send.
func documentAll(entries []*entry, document func(*RPC) (methodDoc, error)) docSummary {
	var d docSummary
	for _, b := range entries {
		for i := range b.rpcs {
			rpc := b.rpcs[i]
			md, err := document(&rpc)
			if md.Method != "" {
				d.methods = append(d.methods, md.Method)
			}
			if err != nil {
				d.notes = append(d.notes, "undocumented: "+err.Error())
				continue
			}
			d.required = append(d.required, md.Required...)
			d.mentioned = append(d.mentioned, md.Mentioned...)
			d.sources = append(
				d.sources,
				fmt.Sprintf("%s → %s (%s)", rpc, md.Method, md.Source),
			)
		}
	}
	return d
}

// extraPermissions returns the permissions e's own rule grants that the
// documentation does not name, split into those not excused and those
// acceptedReasons excuses, each with its reason. A no-permission rule
// grants nothing of its own to be extra.
func extraPermissions(e *entry, docAll map[string]bool) (extra, accepted []string) {
	reasons := acceptedReasons()[e.api]
	for _, p := range keys(lowerSet(e.rule.Perms, e.rule.Maybe)) {
		if docAll[p] {
			continue
		}
		if why, ok := reasons[p]; ok {
			accepted = append(accepted, p+": "+why)
			continue
		}
		extra = append(extra, p)
	}
	return extra, accepted
}

// verdict is the status of a finding whose differences are filled in,
// given the number of RPCs documented.
func verdict(f *finding, documented int) Status {
	switch {
	case len(f.missing) > 0 || len(f.extra) > 0:
		return Mismatch
	case len(f.accepted) > 0:
		return Accepted
	case documented == 0:
		return Unverified
	default:
		return Confirmed
	}
}
