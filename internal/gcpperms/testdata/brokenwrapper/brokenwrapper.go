// Package brokenwrapper holds a wrapper in a package that does not type-check,
// which FindWrappers skips.
package brokenwrapper

import "reflect"

// Call would be a wrapper.
func Call(f any) { reflect.ValueOf(f).Call(nil) }

var _ int = "not an int"
