package gcpperms

import (
	"path"
	"strings"
)

// The rules below are data checked against Google's documentation by
// verify-table, not logic: a mutant that clears a rule's permissions can only
// be caught by a test that restates the table. Mutation testing skips each
// rule literal (a line holding only "{"); lookup, splitAPI, and serviceFor are
// still mutated. .mutago.yml skips the rules' field lines and one-line rules.
//
// mutator-disable-regexp ^\t\{$ composite/field-clear

// rules is the permission table. Check it against Google's documentation
// with gcp-perm-roller verify-table, which reports rules the docs contradict. Sources:
//   - Datastore: https://cloud.google.com/datastore/docs/access/iam
//   - Pub/Sub: https://cloud.google.com/pubsub/docs/access-control
//   - Storage: https://cloud.google.com/storage/docs/access-control/iam-json
//   - BigQuery: https://cloud.google.com/bigquery/docs/access-control
//   - AlloyDB: roles/alloydb.client and roles/serviceusage.serviceUsageConsumer
//
//nolint:gochecknoglobals // read-only table; verify-table parses this declaration from source.
var rules = []rule{
	// Firestore in Datastore mode.
	{
		Pattern: "cloud.google.com/go/datastore.Client.Get",
		Perms:   []string{"datastore.entities.get"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Client.GetMulti",
		Perms:   []string{"datastore.entities.get"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Transaction.Get",
		Perms:   []string{"datastore.entities.get"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Transaction.GetMulti",
		Perms:   []string{"datastore.entities.get"},
	},
	// Put is an upsert.
	{
		Pattern: "cloud.google.com/go/datastore.Client.Put*",
		Perms:   []string{"datastore.entities.create", "datastore.entities.update"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Transaction.Put*",
		Perms:   []string{"datastore.entities.create", "datastore.entities.update"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Client.Delete*",
		Perms:   []string{"datastore.entities.delete"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Transaction.Delete*",
		Perms:   []string{"datastore.entities.delete"},
	},
	// Mutate needs whatever its mutations need; those are mapped below.
	{Pattern: "cloud.google.com/go/datastore.Client.Mutate"},
	{Pattern: "cloud.google.com/go/datastore.Transaction.Mutate"},
	{
		Pattern: "cloud.google.com/go/datastore.NewInsert",
		Perms:   []string{"datastore.entities.create"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.NewUpdate",
		Perms:   []string{"datastore.entities.update"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.NewUpsert",
		Perms:   []string{"datastore.entities.create", "datastore.entities.update"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.NewDelete",
		Perms:   []string{"datastore.entities.delete"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Client.Run",
		Perms:   []string{"datastore.entities.list", "datastore.entities.get"},
		Note:    "keys-only queries need only datastore.entities.list",
	},
	{
		Pattern: "cloud.google.com/go/datastore.Client.RunWithOptions",
		Perms:   []string{"datastore.entities.list", "datastore.entities.get"},
		Note:    "keys-only queries need only datastore.entities.list",
	},
	{
		Pattern: "cloud.google.com/go/datastore.Client.GetAll*",
		Perms:   []string{"datastore.entities.list", "datastore.entities.get"},
		Note:    "keys-only queries need only datastore.entities.list",
	},
	{
		Pattern: "cloud.google.com/go/datastore.Client.Count",
		Perms:   []string{"datastore.entities.list"},
		// Count runs its query keys-only unless the query is a projection.
		Maybe: []string{"datastore.entities.get"},
		Note:  "datastore.entities.get is needed to count a projection query",
	},
	{
		Pattern: "cloud.google.com/go/datastore.Client.RunAggregationQuery*",
		Perms:   []string{"datastore.entities.list"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Transaction.RunAggregationQuery*",
		Perms:   []string{"datastore.entities.list"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Client.AllocateIDs",
		Perms:   []string{"datastore.entities.allocateIds"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Client.ReserveIDs",
		Perms:   []string{"datastore.entities.allocateIds"},
	},
	// BeginTransaction, Rollback, and an empty Commit need databases.get.
	{
		Pattern: "cloud.google.com/go/datastore.Client.NewTransaction",
		Perms:   []string{"datastore.databases.get"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Client.RunInTransaction",
		Perms:   []string{"datastore.databases.get"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Transaction.Commit",
		Perms:   []string{"datastore.databases.get"},
	},
	{
		Pattern: "cloud.google.com/go/datastore.Transaction.Rollback",
		Perms:   []string{"datastore.databases.get"},
	},
	{Pattern: "cloud.google.com/go/datastore.*"},

	// Secret Manager.
	{
		Pattern: "cloud.google.com/go/secretmanager/apiv1.*Client.AccessSecretVersion",
		Perms:   []string{"secretmanager.versions.access"},
	},
	{
		Pattern: "cloud.google.com/go/secretmanager/apiv1.*Client.GetSecretVersion",
		Perms:   []string{"secretmanager.versions.get"},
	},
	{
		Pattern: "cloud.google.com/go/secretmanager/apiv1.*Client.ListSecretVersions",
		Perms:   []string{"secretmanager.versions.list"},
	},
	{
		Pattern: "cloud.google.com/go/secretmanager/apiv1.*Client.AddSecretVersion",
		Perms:   []string{"secretmanager.versions.add"},
	},
	{
		Pattern: "cloud.google.com/go/secretmanager/apiv1.*Client.GetSecret",
		Perms:   []string{"secretmanager.secrets.get"},
	},
	{
		Pattern: "cloud.google.com/go/secretmanager/apiv1.*Client.ListSecrets",
		Perms:   []string{"secretmanager.secrets.list"},
	},
	{
		Pattern: "cloud.google.com/go/secretmanager/apiv1.*Client.CreateSecret",
		Perms:   []string{"secretmanager.secrets.create"},
	},
	{Pattern: "cloud.google.com/go/secretmanager/apiv1.NewClient"},
	{Pattern: "cloud.google.com/go/secretmanager/apiv1.*Client.Close"},
	{Pattern: "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb.*"},

	// Pub/Sub.
	{
		Pattern: "cloud.google.com/go/pubsub/v2.Publisher.Publish",
		Perms:   []string{"pubsub.topics.publish"},
	},
	{
		Pattern: "cloud.google.com/go/pubsub/v2.Subscriber.Receive",
		Perms:   []string{"pubsub.subscriptions.consume"},
	},
	{Pattern: "cloud.google.com/go/pubsub/v2.*"},
	{
		Pattern: "cloud.google.com/go/pubsub/v2/apiv1.TopicAdminClient.GetTopic",
		Perms:   []string{"pubsub.topics.get"},
	},
	// Google documents no permission for ListTopicSubscriptions; this one is
	// unconfirmed (see cmd/verifytable).
	{
		Pattern: "cloud.google.com/go/pubsub/v2/apiv1.TopicAdminClient.ListTopicSubscriptions",
		Perms:   []string{"pubsub.topics.get"},
	},
	{
		Pattern: "cloud.google.com/go/pubsub/v2/apiv1.TopicAdminClient.CreateTopic",
		Perms:   []string{"pubsub.topics.create"},
	},
	{
		Pattern: "cloud.google.com/go/pubsub/v2/apiv1.TopicAdminClient.DeleteTopic",
		Perms:   []string{"pubsub.topics.delete"},
	},
	{
		Pattern: "cloud.google.com/go/pubsub/v2/apiv1.TopicAdminClient.ListTopics",
		Perms:   []string{"pubsub.topics.list"},
	},
	{
		Pattern: "cloud.google.com/go/pubsub/v2/apiv1.SubscriptionAdminClient.CreateSubscription",
		Perms: []string{
			"pubsub.subscriptions.create",
			"pubsub.topics.attachSubscription",
		},
	},
	{
		Pattern: "cloud.google.com/go/pubsub/v2/apiv1.SubscriptionAdminClient.GetSubscription",
		Perms:   []string{"pubsub.subscriptions.get"},
	},
	{
		Pattern: "cloud.google.com/go/pubsub/v2/apiv1.SubscriptionAdminClient.UpdateSubscription",
		Perms:   []string{"pubsub.subscriptions.update"},
	},
	{
		Pattern: "cloud.google.com/go/pubsub/v2/apiv1.SubscriptionAdminClient.DeleteSubscription",
		Perms:   []string{"pubsub.subscriptions.delete"},
	},
	{
		Pattern: "cloud.google.com/go/pubsub/v2/apiv1.SubscriptionAdminClient.ListSubscriptions",
		Perms:   []string{"pubsub.subscriptions.list"},
	},
	{Pattern: "cloud.google.com/go/pubsub/v2/apiv1.*Iterator.*"},
	{Pattern: "cloud.google.com/go/pubsub/v2/apiv1/pubsubpb.*"},
	// In-memory fake server: no RPC to Google.
	{Pattern: "cloud.google.com/go/pubsub/v2/pstest.*"},
	{Pattern: "cloud.google.com/go/internal/pubsub.*"},

	// Cloud Storage.
	{
		Pattern: "cloud.google.com/go/storage.ObjectHandle.New*Reader",
		Perms:   []string{"storage.objects.get"},
	},
	{
		Pattern: "cloud.google.com/go/storage.ObjectHandle.NewMultiRangeDownloader",
		Perms:   []string{"storage.objects.get"},
	},
	{
		Pattern: "cloud.google.com/go/storage.ObjectHandle.Attrs",
		Perms:   []string{"storage.objects.get"},
	},
	{
		Pattern: "cloud.google.com/go/storage.ObjectHandle.NewWriter",
		Perms:   []string{"storage.objects.create"},
		Maybe: []string{
			"storage.objects.delete",
			"storage.objects.get",
		},
		Note: "storage.objects.delete is needed to overwrite an existing object; " +
			"a writer with EnableParallelUpload also composes its parts, which needs storage.objects.get, " +
			"and deletes them, which needs storage.objects.delete",
	},
	{
		Pattern: "cloud.google.com/go/storage.ObjectHandle.Update",
		Perms:   []string{"storage.objects.update"},
	},
	{
		Pattern: "cloud.google.com/go/storage.ObjectHandle.Delete",
		Perms:   []string{"storage.objects.delete"},
	},
	{
		Pattern: "cloud.google.com/go/storage.ObjectHandle.Move",
		Perms:   []string{"storage.objects.move"},
	},
	{
		Pattern: "cloud.google.com/go/storage.ObjectHandle.Restore",
		Perms:   []string{"storage.objects.restore"},
	},
	{
		Pattern: "cloud.google.com/go/storage.Copier.Run",
		Perms:   []string{"storage.objects.get", "storage.objects.create"},
		Maybe: []string{
			"storage.objects.delete",
		},
		Note: "storage.objects.delete is needed to overwrite an existing object",
	},
	{
		Pattern: "cloud.google.com/go/storage.Composer.Run",
		Perms:   []string{"storage.objects.get", "storage.objects.create"},
		Maybe: []string{
			"storage.objects.delete",
		},
		Note: "storage.objects.delete is needed to overwrite an existing object",
	},
	{
		Pattern: "cloud.google.com/go/storage.BucketHandle.Objects",
		Perms:   []string{"storage.objects.list"},
	},
	{
		Pattern: "cloud.google.com/go/storage.BucketHandle.Attrs",
		Perms:   []string{"storage.buckets.get"},
	},
	{
		Pattern: "cloud.google.com/go/storage.BucketHandle.Create",
		Perms:   []string{"storage.buckets.create"},
	},
	{
		Pattern: "cloud.google.com/go/storage.BucketHandle.Update",
		Perms:   []string{"storage.buckets.update"},
	},
	{
		Pattern: "cloud.google.com/go/storage.BucketHandle.Delete",
		Perms:   []string{"storage.buckets.delete"},
	},
	{
		Pattern: "cloud.google.com/go/storage.BucketHandle.Notifications",
		Perms:   []string{"storage.buckets.get"},
	},
	{
		Pattern: "cloud.google.com/go/storage.BucketHandle.AddNotification",
		Perms:   []string{"storage.buckets.update"},
	},
	{
		Pattern: "cloud.google.com/go/storage.BucketHandle.DeleteNotification",
		Perms:   []string{"storage.buckets.update"},
	},
	{
		Pattern: "cloud.google.com/go/storage.Client.Buckets",
		Perms:   []string{"storage.buckets.list"},
	},
	{
		Pattern: "cloud.google.com/go/storage.ACLHandle.List",
		Maybe:   []string{"storage.buckets.getIamPolicy", "storage.objects.getIamPolicy"},
		Note:    "bucket ACLs need storage.buckets.getIamPolicy, object ACLs storage.objects.getIamPolicy",
	},
	{
		Pattern: "cloud.google.com/go/storage.ACLHandle.*",
		Maybe:   []string{"storage.buckets.setIamPolicy", "storage.objects.setIamPolicy"},
		Note:    "bucket ACLs need storage.buckets.setIamPolicy, object ACLs storage.objects.setIamPolicy",
	},
	// A bucket handle signs with IAM signBlob when given no key
	// (bucket.go defaultSignBytesFunc); the package functions sign with the
	// key or SignBytes the caller passes, and send nothing.
	{
		Pattern: "cloud.google.com/go/storage.BucketHandle.SignedURL",
		Maybe:   []string{"iam.serviceAccounts.signBlob"},
		Note:    "signing without a private key calls IAM signBlob on the signing service account",
	},
	{
		Pattern: "cloud.google.com/go/storage.BucketHandle.GenerateSignedPostPolicyV4",
		Maybe:   []string{"iam.serviceAccounts.signBlob"},
		Note:    "signing without a private key calls IAM signBlob on the signing service account",
	},
	{
		Pattern: "cloud.google.com/go/storage.SignedURL",
		Note: "not IAM: signs with the PrivateKey or SignBytes the caller passes, " +
			"so signing needs whatever that function needs",
	},
	{
		Pattern: "cloud.google.com/go/storage.GenerateSignedPostPolicyV4",
		Note: "not IAM: signs with the PrivateKey or SignBytes the caller passes, " +
			"so signing needs whatever that function needs",
	},
	{Pattern: "cloud.google.com/go/storage.*"},

	// BigQuery. Reading tables also needs bigquery.tables.getData on each
	// table a query reads, which static analysis cannot see.
	{
		Pattern: "cloud.google.com/go/bigquery.Query.Run",
		Perms:   []string{"bigquery.jobs.create"},
		Note:    "the query also needs bigquery.tables.getData on every table it reads",
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Query.Read",
		// Reading the results calls jobs.getQueryResults, which needs
		// bigquery.tables.getData on the query's destination table.
		Perms: []string{
			"bigquery.jobs.create",
			"bigquery.jobs.get",
			"bigquery.tables.getData",
		},
		// With the Storage Read API enabled, results come from a read
		// session on the destination table, whose schema is fetched first.
		Maybe: []string{
			"bigquery.readsessions.create",
			"bigquery.readsessions.getData",
			"bigquery.tables.get",
		},
		Note: "the query also needs bigquery.tables.getData on every table it reads; a client " +
			"with the Storage Read API enabled (EnableStorageReadClient) also needs " +
			"bigquery.tables.get and bigquery.readsessions.create and .getData",
	},
	{
		// Waiting for a query job calls jobs.getQueryResults.
		Pattern: "cloud.google.com/go/bigquery.Job.Wait",
		Perms:   []string{"bigquery.jobs.get"},
		Maybe:   []string{"bigquery.tables.getData"},
		Note:    "waiting for a query job also needs bigquery.tables.getData on its destination table",
	},
	{Pattern: "cloud.google.com/go/bigquery.Job.Status", Perms: []string{"bigquery.jobs.get"}},
	{
		Pattern: "cloud.google.com/go/bigquery.Job.Read",
		Perms:   []string{"bigquery.jobs.get", "bigquery.tables.getData"},
		Maybe: []string{
			"bigquery.readsessions.create",
			"bigquery.readsessions.getData",
			"bigquery.tables.get",
		},
		Note: "a client with the Storage Read API enabled (EnableStorageReadClient) also needs " +
			"bigquery.tables.get and bigquery.readsessions.create and .getData",
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Job.Cancel",
		Perms:   []string{"bigquery.jobs.update"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Job.Delete",
		Perms:   []string{"bigquery.jobs.delete"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Client.JobFrom*",
		Perms:   []string{"bigquery.jobs.get"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Client.Jobs",
		Perms:   []string{"bigquery.jobs.list"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Inserter.Put",
		Perms: []string{
			"bigquery.datasets.get",
			"bigquery.tables.get",
			"bigquery.tables.updateData",
		},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Loader.Run",
		Perms: []string{
			"bigquery.jobs.create",
			"bigquery.tables.create",
			"bigquery.tables.updateData",
		},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Extractor.Run",
		Perms:   []string{"bigquery.jobs.create", "bigquery.tables.export"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Copier.Run",
		Perms: []string{
			"bigquery.jobs.create",
			"bigquery.tables.getData",
			"bigquery.tables.create",
			"bigquery.tables.updateData",
		},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Table.Read",
		Perms:   []string{"bigquery.tables.getData"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Table.Create",
		Perms:   []string{"bigquery.tables.create"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Table.Metadata",
		Perms:   []string{"bigquery.tables.get"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Table.Update",
		Perms:   []string{"bigquery.tables.get", "bigquery.tables.update"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Table.Delete",
		Perms:   []string{"bigquery.tables.delete"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Dataset.Tables",
		Perms:   []string{"bigquery.tables.list"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Dataset.Create*",
		Perms:   []string{"bigquery.datasets.create"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Dataset.Metadata*",
		Perms:   []string{"bigquery.datasets.get"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Dataset.Update*",
		Perms:   []string{"bigquery.datasets.update"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Dataset.Delete*",
		Perms:   []string{"bigquery.datasets.delete"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Client.Datasets*",
		Perms:   []string{"bigquery.datasets.get"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Model.Metadata",
		Perms:   []string{"bigquery.models.getMetadata"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Model.Update",
		Perms:   []string{"bigquery.models.updateMetadata"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Model.Delete",
		Perms:   []string{"bigquery.models.delete"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Routine.Create",
		Perms:   []string{"bigquery.routines.create"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Routine.Metadata",
		Perms:   []string{"bigquery.routines.get"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Routine.Update",
		Perms:   []string{"bigquery.routines.update"},
	},
	{
		Pattern: "cloud.google.com/go/bigquery.Routine.Delete",
		Perms:   []string{"bigquery.routines.delete"},
	},
	{Pattern: "cloud.google.com/go/bigquery.*"},

	// Artifact Registry.
	{
		Pattern: "cloud.google.com/go/artifactregistry/apiv1.Client.ListRepositories",
		Perms:   []string{"artifactregistry.repositories.list"},
	},
	{
		Pattern: "cloud.google.com/go/artifactregistry/apiv1.Client.GetRepository",
		Perms:   []string{"artifactregistry.repositories.get"},
	},
	{
		Pattern: "cloud.google.com/go/artifactregistry/apiv1.Client.ListDockerImages",
		Perms:   []string{"artifactregistry.dockerimages.list"},
	},
	{
		Pattern: "cloud.google.com/go/artifactregistry/apiv1.Client.GetDockerImage",
		Perms:   []string{"artifactregistry.dockerimages.get"},
	},
	{
		Pattern: "cloud.google.com/go/artifactregistry/apiv1.Client.ListTags",
		Perms:   []string{"artifactregistry.tags.list"},
	},
	{
		Pattern: "cloud.google.com/go/artifactregistry/apiv1.Client.GetTag",
		Perms:   []string{"artifactregistry.tags.get"},
	},
	{
		Pattern: "cloud.google.com/go/artifactregistry/apiv1.Client.ListVersions",
		Perms:   []string{"artifactregistry.versions.list"},
	},
	{Pattern: "cloud.google.com/go/artifactregistry/apiv1.NewClient"},
	{Pattern: "cloud.google.com/go/artifactregistry/apiv1.Client.Close"},
	{Pattern: "cloud.google.com/go/artifactregistry/apiv1.*Iterator.*"},
	{Pattern: "cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb.*"},

	// IAM Service Account Credentials: grants on the target service account.
	// The patterns also match the unexported iamCredentialsGRPCClient and
	// iamCredentialsRESTClient, which a caller reaches when it holds the
	// client through an interface of its own.
	{
		Pattern: "cloud.google.com/go/iam/credentials/apiv1.*amCredentials*Client.SignBlob",
		Perms:   []string{"iam.serviceAccounts.signBlob"},
	},
	{
		Pattern: "cloud.google.com/go/iam/credentials/apiv1.*amCredentials*Client.SignJwt",
		Perms:   []string{"iam.serviceAccounts.signJwt"},
	},
	{
		Pattern: "cloud.google.com/go/iam/credentials/apiv1.*amCredentials*Client.GenerateAccessToken",
		Perms:   []string{"iam.serviceAccounts.getAccessToken"},
	},
	{
		Pattern: "cloud.google.com/go/iam/credentials/apiv1.*amCredentials*Client.GenerateIdToken",
		Perms:   []string{"iam.serviceAccounts.getOpenIdToken"},
	},
	{Pattern: "cloud.google.com/go/iam/credentials/apiv1.NewIamCredentialsClient"},
	{Pattern: "cloud.google.com/go/iam/credentials/apiv1.*amCredentials*Client.Close"},
	{Pattern: "cloud.google.com/go/iam/credentials/apiv1/credentialspb.*"},

	// AlloyDB connector: the dialer fetches a client certificate and the
	// instance's connection info before each connection refresh.
	{
		Pattern: "cloud.google.com/go/alloydbconn.Dialer.Dial",
		Perms: []string{
			"alloydb.clusters.generateClientCertificate",
			"alloydb.instances.connect",
			"alloydb.instances.get",
			"serviceusage.services.use",
		},
	},
	{
		Pattern: "cloud.google.com/go/alloydbconn.WithIAMAuthN",
		Perms:   []string{"alloydb.users.login"},
		Note:    "IAM database authentication; the principal must also be an IAM database user",
	},
	{Pattern: "cloud.google.com/go/alloydbconn.*"},

	// Cloud Monitoring and Cloud Trace exporters for OpenTelemetry.
	{
		Pattern: "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric.New",
		Perms:   []string{"monitoring.timeSeries.create"},
		Maybe:   []string{"monitoring.metricDescriptors.create"},
		Note:    "monitoring.metricDescriptors.create is needed unless descriptor creation is disabled",
	},
	{
		Pattern: "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace.New",
		Perms:   []string{"cloudtrace.traces.patch"},
	},
	{Pattern: "github.com/GoogleCloudPlatform/opentelemetry-operations-go/*"},

	// Google Workspace APIs authorize with OAuth scopes and Drive sharing,
	// not IAM; they only need the API enabled in the quota project.
	{
		Pattern: "google.golang.org/api/sheets/v4.*Call.Do",
		Note:    "not IAM: needs an OAuth scope such as spreadsheets and access to the spreadsheet",
	},
	{
		Pattern: "google.golang.org/api/drive/v3.*Call.Do",
		Note:    "not IAM: needs an OAuth scope such as drive and access to the files",
	},
	{Pattern: "google.golang.org/api/sheets/v4.*"},
	{Pattern: "google.golang.org/api/drive/v3.*"},

	// Dataflow REST API.
	{
		Pattern: "google.golang.org/api/dataflow/v1b3.ProjectsLocationsTemplatesLaunchCall.Do",
		Perms:   []string{"dataflow.jobs.create"},
	},
	{
		Pattern: "google.golang.org/api/dataflow/v1b3.ProjectsLocationsFlexTemplatesLaunchCall.Do",
		Perms:   []string{"dataflow.jobs.create"},
	},
	{
		Pattern: "google.golang.org/api/dataflow/v1b3.ProjectsLocationsJobsGetCall.Do",
		Perms:   []string{"dataflow.jobs.get"},
	},
	{
		Pattern: "google.golang.org/api/dataflow/v1b3.ProjectsLocationsJobsListCall.Do",
		Perms:   []string{"dataflow.jobs.list"},
	},
	{
		Pattern: "google.golang.org/api/dataflow/v1b3.ProjectsLocationsJobsUpdateCall.Do",
		Maybe:   []string{"dataflow.jobs.cancel", "dataflow.jobs.updateContents"},
		Note:    "dataflow.jobs.cancel is needed to cancel a job, dataflow.jobs.updateContents to update its runtime parameters",
	},
	{Pattern: "google.golang.org/api/dataflow/v1b3.*Call.Do"},
	{Pattern: "google.golang.org/api/dataflow/v1b3.*"},

	// Cloud Tasks. These rules cover App Engine tasks and HTTP tasks without
	// a token; see the note for tasks that carry one.
	{
		Pattern: "cloud.google.com/go/cloudtasks/apiv2.*Client.CreateTask",
		Perms:   []string{"cloudtasks.tasks.create"},
		Note: "an HTTP task with an OIDC or OAuth token also needs iam.serviceAccounts.actAs " +
			"on the service account the token is for",
	},
	{
		Pattern: "cloud.google.com/go/cloudtasks/apiv2.*Client.DeleteTask",
		Perms:   []string{"cloudtasks.tasks.delete"},
	},
	{
		Pattern: "cloud.google.com/go/cloudtasks/apiv2.*Client.GetTask",
		Perms:   []string{"cloudtasks.tasks.get"},
	},
	{
		Pattern: "cloud.google.com/go/cloudtasks/apiv2.*Client.ListTasks",
		Perms:   []string{"cloudtasks.tasks.list"},
	},
	{
		Pattern: "cloud.google.com/go/cloudtasks/apiv2.*Client.RunTask",
		Perms:   []string{"cloudtasks.tasks.run"},
	},
	{Pattern: "cloud.google.com/go/cloudtasks/apiv2.NewClient"},
	{Pattern: "cloud.google.com/go/cloudtasks/apiv2.NewRESTClient"},
	{Pattern: "cloud.google.com/go/cloudtasks/apiv2.*Client.Close"},
	{Pattern: "cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb.*"},

	// Cloud Profiler: the agent Start launches creates a profile, then
	// uploads it, in the background for the life of the process.
	{
		Pattern: "cloud.google.com/go/profiler.Start",
		Perms:   []string{"cloudprofiler.profiles.create", "cloudprofiler.profiles.update"},
	},

	// Authentication plumbing: credentials come from the environment or
	// the metadata server, and ID token validation fetches public keys.
	{Pattern: "google.golang.org/api/option.*"},
	{Pattern: "google.golang.org/api/iterator.*"},
	{Pattern: "google.golang.org/api/googleapi.*"},
	{Pattern: "google.golang.org/api/idtoken.*"},
	{Pattern: "google.golang.org/api/oauth2/v2.*"},
	{Pattern: "golang.org/x/oauth2/google.*"},
	{Pattern: "cloud.google.com/go/compute/metadata.*"},
	{Pattern: "cloud.google.com/go/auth.*"},
	{Pattern: "cloud.google.com/go/civil.*"},
}

// rule maps SDK entry points to what calling them requires.
//
// Pattern is "importpath.Name", where Name is "Func" or "Type.Method" and
// may use path.Match globs ("Query.*", "*Call.Fields"). The first matching
// rule wins, so put specific rules before broad ones.
//
// A rule with no Perms, Maybe, or Note marks an entry point that makes no
// RPC (constructors, builders, accessors); such calls are dropped from the
// report. Permissions are attributed to the call that sends the request: for
// iterators that is the call that creates the iterator, and for writers it
// is the call that opens the writer.
type rule struct {
	Pattern string
	// Perms are always required.
	Perms []string
	// Maybe are required only on some paths, described by Note.
	Maybe []string
	Note  string
}

func (r *rule) noop() bool {
	return len(r.Perms) == 0 && len(r.Maybe) == 0 && r.Note == ""
}

// services maps import-path prefixes to the API that must be enabled.
func services() []struct{ prefix, service string } {
	return []struct{ prefix, service string }{
		{"cloud.google.com/go/datastore", "datastore.googleapis.com"},
		{"cloud.google.com/go/secretmanager", "secretmanager.googleapis.com"},
		{"cloud.google.com/go/pubsub", "pubsub.googleapis.com"},
		{"cloud.google.com/go/storage", "storage.googleapis.com"},
		{"cloud.google.com/go/bigquery", "bigquery.googleapis.com"},
		{"cloud.google.com/go/artifactregistry", "artifactregistry.googleapis.com"},
		{"cloud.google.com/go/iam/credentials", "iamcredentials.googleapis.com"},
		{"cloud.google.com/go/cloudtasks", "cloudtasks.googleapis.com"},
		{"cloud.google.com/go/profiler", "cloudprofiler.googleapis.com"},
		{"cloud.google.com/go/alloydbconn", "alloydb.googleapis.com"},
		{
			"github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric",
			"monitoring.googleapis.com",
		},
		{
			"github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace",
			"cloudtrace.googleapis.com",
		},
		{"google.golang.org/api/sheets", "sheets.googleapis.com"},
		{"google.golang.org/api/drive", "drive.googleapis.com"},
		{"google.golang.org/api/dataflow", "dataflow.googleapis.com"},
	}
}

func serviceFor(api string) string {
	for _, s := range services() {
		if strings.HasPrefix(api, s.prefix) {
			return s.service
		}
	}
	return ""
}

// splitAPI splits "a/b/c.T.M" into "a/b/c" and "T.M".
func splitAPI(api string) (pkg, name string) {
	slash := strings.LastIndex(api, "/")
	dot := strings.Index(api[slash+1:], ".")
	if dot < 0 {
		return api, ""
	}
	return api[:slash+1+dot], api[slash+2+dot:]
}

// lookup returns the first rule matching api.
func lookup(api string) (rule, bool) {
	pkg, name := splitAPI(api)
	for _, r := range rules {
		rpkg, rname := splitAPI(r.Pattern)
		if strings.HasSuffix(rpkg, "*") {
			// A package-path glob such as "github.com/x/y/*".
			if !strings.HasPrefix(pkg, strings.TrimSuffix(rpkg, "*")) {
				continue
			}
		} else if rpkg != pkg {
			continue
		}
		if ok, _ := path.Match(rname, name); ok || rname == "" {
			return r, true
		}
	}
	return rule{}, false
}
