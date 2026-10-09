package gcpperms

import _ "embed"

// TableSource is the source of table.go, for tools that check the rules
// independently of this package by parsing them.
//
//go:embed table.go
var TableSource []byte
