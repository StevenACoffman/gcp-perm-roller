// Command broken is a fixture that does not type-check.
package main

func main() {
	var n int = "not an int"
	_ = n
}
