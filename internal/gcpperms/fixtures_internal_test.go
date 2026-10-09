package gcpperms

// The programs in testdata import these SDK packages, but go mod tidy does
// not look in testdata. Importing them here keeps their modules, at the
// versions the golden files were made with, in go.mod.
import (
	_ "cloud.google.com/go/datastore"
	_ "cloud.google.com/go/secretmanager/apiv1"
	_ "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	_ "cloud.google.com/go/storage"
	_ "github.com/googleapis/google-cloud-go-testing/datastore/dsiface"
)
