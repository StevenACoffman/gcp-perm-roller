// Package wrappers holds functions that call the functions passed to them by
// reflection, which FindWrappers must find, and near misses it must not.
package wrappers

import "reflect"

// Cache memoizes f by building a function with reflect.MakeFunc.
func Cache[T any](f T) T {
	v := reflect.ValueOf(f)
	return reflect.MakeFunc(v.Type(), func(args []reflect.Value) []reflect.Value {
		return v.Call(args)
	}).Interface().(T)
}

// Call calls f by reflection.
func Call(f any) { reflect.ValueOf(f).Call(nil) }

// Spread calls its second parameter with the arguments in the first.
func Spread(args []reflect.Value, f any) { reflect.ValueOf(f).CallSlice(args) }

// Later calls f by reflection in a closure it returns.
func Later(f func()) func() {
	return func() {
		func() { reflect.ValueOf(f).Call(nil) }()
	}
}

// Both calls each of two functions.
func Both(a, b func()) {
	reflect.ValueOf(a).Call(nil)
	reflect.ValueOf(b).Call(nil)
}

// Memo builds its function from a helper, as a cache that checks results
// does: the call happens two functions away.
func Memo[T any](f T) T {
	v := reflect.ValueOf(f)
	return reflect.MakeFunc(v.Type(), wrap(v)).Interface().(T)
}

func wrap(v reflect.Value) func([]reflect.Value) []reflect.Value {
	return func(args []reflect.Value) []reflect.Value { return invoke(v, args) }
}

func invoke(v reflect.Value, args []reflect.Value) []reflect.Value { return v.Call(args) }

// Chain calls f through a method value its helper takes, as a cache with
// several layers does: next := v.Call.
func Chain[T any](f T) T {
	v := reflect.ValueOf(f)
	return reflect.MakeFunc(v.Type(), layer(v)).Interface().(T)
}

func layer(v reflect.Value) func([]reflect.Value) []reflect.Value {
	next := v.Call
	return func(args []reflect.Value) []reflect.Value { return next(args) }
}

// TypeOnly inspects f by reflection but never calls it.
func TypeOnly(f any) string { return reflect.ValueOf(f).Type().String() }

// CallsAnother calls a function it made itself, not the one passed to it.
func CallsAnother(f any) {
	_ = reflect.ValueOf(f).Kind()
	reflect.ValueOf(func() {}).Call(nil)
}

// Runner holds a method that calls by reflection; methods are not wrappers.
type Runner struct{}

// Run calls f by reflection.
func (Runner) Run(f any) { reflect.ValueOf(f).Call(nil) }

func use() {
	_ = Cache(func() int { return 1 })
	_ = Cache(func() string { return "" })
	Call(func() {})
	Later(func() {})()
	Both(func() {}, func() {})
	Runner{}.Run(func() {})
	_ = Memo(func() {})
	_ = Chain(func() {})
}
