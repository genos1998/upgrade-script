package graphqlfunc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
)

type S3Client struct {
	S3Client *s3.Client
	endpoint *url.URL
}

func CleanS3Name(name string) string {
	return strings.ReplaceAll(name, ":", "-")
}

func (*S3Client) MakeS3Key(bucket, prefix, name string) string {
	keyparts := []string{bucket}
	if prefix != "" {
		keyparts = append(keyparts, prefix)
	}
	keyparts = append(keyparts, CleanS3Name(name))
	return path.Join(keyparts...)
}

// Override the default endpoint resolver if needed
func (mgr *S3Client) ResolveEndpoint(ctx context.Context, params s3.EndpointParameters) (smithyendpoints.Endpoint, error) {
	return smithyendpoints.Endpoint{
		URI: *mgr.endpoint,
	}, nil
}

func makeAWSConfig(ctx context.Context) (aws.Config, error) {
	httpClient := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.MinVersion = tls.VersionTLS13
	})

	return config.LoadDefaultConfig(ctx,
		config.WithHTTPClient(httpClient),
		config.WithClientLogMode(aws.LogDeprecatedUsage),
	)
}

func MakeS3Client(ctx context.Context, endpoint string) (*S3Client, error) {

	cfg, err := makeAWSConfig(ctx)
	if err != nil {
		err = fmt.Errorf("MakeS3Client: unable to make aws config %s", err.Error())
		return nil, err
	}

	client := &S3Client{}

	uri, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	client.endpoint = uri

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if client.endpoint != nil {
			o.EndpointResolverV2 = client
		}
	})
	client.S3Client = s3Client

	return client, nil
}

func (u *S3Client) upload(ctx context.Context, bucketName, key string, outfile *os.File) error {

	partMBS := int64(10)
	if _, err := outfile.Seek(0, 0); err != nil {
		return err
	}

	uploader := manager.NewUploader(u.S3Client, func(u *manager.Uploader) {
		u.PartSize = partMBS * 1024 * 1024
	})

	_, err := uploader.Upload(ctx, &s3.PutObjectInput{
		ACL:         types.ObjectCannedACLBucketOwnerFullControl,
		Bucket:      aws.String(bucketName),
		Key:         aws.String(key),
		Body:        outfile,
		Tagging:     aws.String("ItemType=docker-image"),
		ContentType: aws.String("application/tar+gzip"),
	})
	return err
}
