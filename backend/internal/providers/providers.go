package providers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	giterator "google.golang.org/api/iterator"

	"github.com/mohdsaad0786/maestro/backend/internal/core"
)

type Scanner interface {
	Discover(context.Context) ([]core.Resource, error)
}

func New(name string) (Scanner, error) {
	switch name {
	case "aws":
		return awsScanner{}, nil
	case "gcp":
		return gcpScanner{}, nil
	case "azure":
		return azureScanner{}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %q", name)
	}
}

type awsScanner struct{}

func (awsScanner) Discover(ctx context.Context) ([]core.Resource, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("AWS credentials: %w", err)
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("AWS account identity: %w", err)
	}
	account := aws.ToString(identity.Account)
	if account == "" {
		return nil, errors.New("AWS account identity is empty")
	}
	client := s3.NewFromConfig(cfg)
	parent := "aws:account:" + account
	resources := []core.Resource{{ID: parent, Provider: "aws", Kind: "account", Name: account, Attributes: map[string]string{}}}
	pager := s3.NewListBucketsPaginator(client, &s3.ListBucketsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list S3 buckets: %w", err)
		}
		for _, bucket := range page.Buckets {
			name := aws.ToString(bucket.Name)
			if name == "" {
				return nil, errors.New("S3 returned a bucket without a name")
			}
			block, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(name)})
			publicBlocked := false
			if err != nil && !apiCode(err, "NoSuchPublicAccessBlockConfiguration") {
				return nil, fmt.Errorf("S3 %s public access: %w", name, err)
			}
			if err == nil {
				if block.PublicAccessBlockConfiguration == nil {
					return nil, fmt.Errorf("S3 %s returned an empty public access block", name)
				}
				config := block.PublicAccessBlockConfiguration
				publicBlocked = aws.ToBool(config.BlockPublicAcls) && aws.ToBool(config.BlockPublicPolicy) && aws.ToBool(config.IgnorePublicAcls) && aws.ToBool(config.RestrictPublicBuckets)
			}
			encryption, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(name)})
			encrypted := err == nil
			if err != nil && !apiCode(err, "ServerSideEncryptionConfigurationNotFoundError") {
				return nil, fmt.Errorf("S3 %s encryption: %w", name, err)
			}
			if err == nil && (encryption.ServerSideEncryptionConfiguration == nil || len(encryption.ServerSideEncryptionConfiguration.Rules) == 0) {
				return nil, fmt.Errorf("S3 %s returned an empty encryption configuration", name)
			}
			resources = append(resources, core.Resource{ID: "aws:s3:bucket:" + name, Provider: "aws", Kind: "bucket", Name: name, ParentID: parent, Attributes: map[string]string{"publicAccessBlocked": fmt.Sprint(publicBlocked), "defaultEncryption": fmt.Sprint(encrypted)}})
		}
	}
	return resources, nil
}

func apiCode(err error, code string) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == code
}

type gcpScanner struct{}

func (gcpScanner) Discover(ctx context.Context) ([]core.Resource, error) {
	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		return nil, errors.New("GOOGLE_CLOUD_PROJECT is required")
	}
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("GCP credentials: %w", err)
	}
	defer client.Close()
	parent := "gcp:project:" + project
	resources := []core.Resource{{ID: parent, Provider: "gcp", Kind: "project", Name: project, Attributes: map[string]string{}}}
	buckets := client.Buckets(ctx, project)
	for {
		attrs, err := buckets.Next()
		if errors.Is(err, giterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list GCS buckets: %w", err)
		}
		if attrs.Name == "" || attrs.PublicAccessPrevention == storage.PublicAccessPreventionUnknown {
			return nil, errors.New("GCS bucket missing required security configuration")
		}
		prevention := "inherited"
		if attrs.PublicAccessPrevention == storage.PublicAccessPreventionEnforced {
			prevention = "enforced"
		}
		resources = append(resources, core.Resource{ID: "gcp:gcs:bucket:" + attrs.Name, Provider: "gcp", Kind: "bucket", Name: attrs.Name, ParentID: parent, Region: attrs.Location, Attributes: map[string]string{"uniformAccess": fmt.Sprint(attrs.UniformBucketLevelAccess.Enabled), "publicAccessPrevention": prevention}})
	}
	return resources, nil
}

type azureScanner struct{}

func (azureScanner) Discover(ctx context.Context) ([]core.Resource, error) {
	subscription := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subscription == "" {
		return nil, errors.New("AZURE_SUBSCRIPTION_ID is required")
	}
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("Azure credentials: %w", err)
	}
	client, err := armstorage.NewAccountsClient(subscription, credential, nil)
	if err != nil {
		return nil, fmt.Errorf("Azure storage client: %w", err)
	}
	parent := "azure:subscription:" + subscription
	resources := []core.Resource{{ID: parent, Provider: "azure", Kind: "subscription", Name: subscription, Attributes: map[string]string{}}}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list Azure storage accounts: %w", err)
		}
		for _, account := range page.Value {
			if account == nil || account.ID == nil || account.Name == nil || account.Properties == nil || account.Properties.EnableHTTPSTrafficOnly == nil || account.Properties.AllowBlobPublicAccess == nil || account.Properties.MinimumTLSVersion == nil {
				return nil, errors.New("Azure storage account missing required security configuration")
			}
			tls := string(*account.Properties.MinimumTLSVersion)
			resources = append(resources, core.Resource{ID: strings.ToLower(*account.ID), Provider: "azure", Kind: "storage_account", Name: *account.Name, ParentID: parent, Region: stringValue(account.Location), Attributes: map[string]string{"httpsOnly": fmt.Sprint(*account.Properties.EnableHTTPSTrafficOnly), "publicBlobAccess": fmt.Sprint(*account.Properties.AllowBlobPublicAccess), "tlsAtLeast12": fmt.Sprint(tls == "TLS1_2" || tls == "TLS1_3")}})
		}
	}
	return resources, nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
