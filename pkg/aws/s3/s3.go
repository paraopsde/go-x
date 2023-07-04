package s3

import (
	"bytes"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type Uploader struct {
	bucket string
	region string
}

func NewUploader(bucket, region string) *Uploader {
	return &Uploader{
		bucket: bucket,
		region: region,
	}
}

func (u *Uploader) Upload(ctx context.Context, key string, data []byte) error {

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config:            aws.Config{Region: aws.String(u.region)},
		SharedConfigState: session.SharedConfigEnable,
	}))

	s3Client := s3.New(sess)

	_, err := s3Client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: aws.String(u.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("failed to upload PDF file to S3: %w", err)
	}

	return nil
}
