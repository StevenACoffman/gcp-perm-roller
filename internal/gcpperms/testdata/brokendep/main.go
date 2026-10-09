// Command brokendep is a fixture that type-checks but imports a package
// that does not.
package main

import "github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms/testdata/brokenlib"

func main() {
	_ = brokenlib.N
}
