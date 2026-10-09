package gcpperms

// A table whose one rule grants a permission that does not exist.
var rules = []rule{
	{
		Pattern: "cloud.google.com/go/datastore.Client.Get",
		Perms:   []string{"datastore.entities.bogus"},
	},
}
