package gcpperms

import (
	"testing"
)

// fakeWrappers holds wrappers, and near misses, that the fixture FindWrappers
// loads does not: each pins one step of how a call by reflection is traced
// back to a parameter.
const fakeWrappers = `package w

import "reflect"

// Call is the plainest wrapper.
func Call(f any) { reflect.ValueOf(f).Call(nil) }

// Either calls whichever function it picks.
func Either(a, b func(), pickA bool) {
	v := reflect.ValueOf(b)
	if pickA {
		v = reflect.ValueOf(a)
	}
	v.Call(nil)
}

// Swap calls one of two functions it may swap any number of times.
func Swap(a, b func(), n int) {
	v, w := reflect.ValueOf(a), reflect.ValueOf(b)
	for range n {
		v, w = w, v
	}
	v.Call(nil)
}

// Mixed calls either a reflect.Value it is given or the function it is
// given, made into one.
func Mixed(v reflect.Value, f any, useF bool) {
	x := reflect.ValueOf(f)
	if !useF {
		x = v
	}
	x.Call(nil)
}

// ViaMixed is a wrapper of what it passes Mixed to call.
func ViaMixed(f, g func()) { Mixed(reflect.ValueOf(f), g, false) }

// Generic calls by reflection through an instance of a generic helper.
func Generic(f func()) { gcall(reflect.ValueOf(f), 0) }

func gcall[T any](v reflect.Value, _ T) { v.Call(nil) }

// Instanced calls Call, and Instanced[int] is the one instance of it.
func Instanced[T any](f func()) { Call(f) }

// Atop calls by reflection three functions away, through helpers that
// sort after it: finding it takes several rounds of summaries.
func Atop(f func()) { bHelp(reflect.ValueOf(f)) }

func bHelp(v reflect.Value) {
	cHelp(v)
	cHelp(v)
}

func cHelp(v reflect.Value) { v.Call(nil) }

// Closures captures two functions, and only the closure that captures f
// calls it.
func Closures(f, g func()) {
	a := func() { reflect.ValueOf(f).Call(nil) }
	b := func() { _ = reflect.ValueOf(g).Kind() }
	a()
	b()
}

// Deferred passes the closure that calls f to a function that is not
// reflect.MakeFunc.
func Deferred(f any) { run(func() { reflect.ValueOf(f).Call(nil) }) }

func run(g func()) { g() }

// MakeZero calls the zero function of a type, not a function passed in.
func MakeZero(t reflect.Type) { reflect.Zero(t).Call(nil) }

// Value and ValueOf are named like reflect's but are not reflect's.
type Value struct{}

func (Value) Call([]reflect.Value) {}

func ValueOf(any) Value { return Value{} }

// Lookalike calls a method named like reflect.Value.Call.
func Lookalike(f func()) { ValueOf(f).Call(nil) }

// Thunk calls error.Error, a method of no package, through a method
// expression.
func Thunk(err error) string {
	f := error.Error
	return f(err)
}

func use() {
	Instanced[int](func() {})
}

// Literal holds a function literal that calls its own parameter by
// reflection, which is no declared function and so no wrapper, and a
// closure that calls Call, whose call is counted once.
func Literal() {
	call := func(f any) { reflect.ValueOf(f).Call(nil) }
	call(Literal)
	func() { Call(Literal) }()
}
`

// fakeOther is a wrapper in a package findWrappers is not asked about.
const fakeOther = `package other

import "reflect"

func Call(f any) { reflect.ValueOf(f).Call(nil) }
`

func TestFindWrappersInSSA(t *testing.T) {
	_, pkgs := buildSSA(t,
		[2]string{"example.com/w", fakeWrappers},
		[2]string{"example.com/other", fakeOther},
	)
	const w = "example.com/w."
	type found struct {
		function string
		params   []int
		calls    int
		reason   string
	}
	var got []found
	for _, wr := range findWrappers(pkgs[:1], "") {
		got = append(got, found{wr.Function, wr.Params, wr.Calls, wr.Reason})
	}
	const direct = "with reflect.Value.Call"
	reason := func(params, how string) string {
		return "passes parameter " + params + " to reflect.ValueOf and calls it " + how
	}
	// spec: values are traced through phis, loops, helpers at any depth,
	// generic instances, and the one closure a free variable is bound in;
	// a closure passed to a function other than reflect.MakeFunc is not
	// built with it; a reflect.Value not made from a parameter, functions
	// named like reflect's, and wrappers in packages not asked about are not
	// wrappers; a generic wrapper's calls are counted once, not again in its
	// instances; a function literal is not a wrapper, and a call in a
	// closure is counted once.
	equals(t, got, []found{
		{w + "Atop", []int{0}, 0, reason("0", "through bHelp")},
		{w + "Call", []int{0}, 2, reason("0", direct)},
		{w + "Closures", []int{0}, 0, reason("0", direct)},
		{w + "Deferred", []int{0}, 0, reason("0", direct)},
		{w + "Either", []int{0, 1}, 0, reason("0, 1", direct)},
		{w + "Generic", []int{0}, 0, reason("0", "through gcall")},
		{w + "Mixed", []int{1}, 1, reason("1", direct)},
		{w + "Swap", []int{0, 1}, 0, reason("0, 1", direct)},
		{w + "ViaMixed", []int{0}, 0, reason("0", "through Mixed")},
	})

	// spec: no packages have no wrappers.
	equals(t, len(findWrappers(nil, "")), 0)
}
