package iam

import (
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type dynamoSession struct {
	table  string
	awsSvc *session.Session
}

type dynamoUser struct {
	Id          string
	EMail       string
	Name        string
	Disabled    bool
	Permissions []string
}

var EmptyResultError = errors.New("empty result")

func newDynamoSession(awssvc *session.Session) (*dynamoSession, error) {
	var err error
	if awssvc == nil {
		awssvc, err = getAwsSession()
		if err != nil {
			return nil, fmt.Errorf("backend initialization failed: %w", err)
		}
	}
	table := os.Getenv("DYNAMODB_TABLE")
	if table == "" {
		return nil, fmt.Errorf("DYNAMODB_TABLE must point to dynamodb table")
	}
	dynamo := &dynamoSession{
		table:  table,
		awsSvc: awssvc,
	}
	return dynamo, nil
}

func getAwsSession() (*session.Session, error) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	conf := &aws.Config{
		Region: aws.String(region),
	}
	return session.NewSession(conf)
}

func (dynctx *dynamoSession) getUser(uid string) (*dynamoUser, error) {
	svc := dynamodb.New(dynctx.awsSvc)

	table := dynctx.userTable()
	dynamoItem, err := getDynamoItem(svc, table, uid)
	if errors.Is(err, EmptyResultError) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get record for user %q from dynamo table %q: %w", uid, table, err)
	}

	user := &dynamoUser{}
	err = dynamodbattribute.UnmarshalMap(dynamoItem, &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user %q from table %q, %v", uid, table, err)
	}

	return user, nil
}

func getDynamoItem(svc *dynamodb.DynamoDB, table, id string) (map[string]*dynamodb.AttributeValue, error) {
	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"Id": {
				S: aws.String(id),
			},
		},
		TableName:      aws.String(table),
		ConsistentRead: aws.Bool(true),
	}

	result, err := svc.GetItem(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeProvisionedThroughputExceededException:
				return nil, fmt.Errorf("getitem error %v: %v",
					dynamodb.ErrCodeProvisionedThroughputExceededException, aerr.Error())
			case dynamodb.ErrCodeResourceNotFoundException:
				return nil, fmt.Errorf("getitem error %v: %v",
					dynamodb.ErrCodeResourceNotFoundException, aerr.Error())
			case dynamodb.ErrCodeRequestLimitExceeded:
				return nil, fmt.Errorf("getitem error %v: %v",
					dynamodb.ErrCodeRequestLimitExceeded, aerr.Error())
			case dynamodb.ErrCodeInternalServerError:
				return nil, fmt.Errorf("getitem error %v: %v",
					dynamodb.ErrCodeInternalServerError, aerr.Error())
			default:
				return nil, fmt.Errorf("getitem error (default): %v", aerr.Error())
			}
		}
		return nil, fmt.Errorf("non-aws error: %v", err.Error())
	}

	if len(result.Item) == 0 {
		return nil, fmt.Errorf("%q in %q: %w", id, table, EmptyResultError)
	}
	//fmt.Printf("GetItem result.Item: %v\n", result.Item)
	return result.Item, nil
}

func (dynctx *dynamoSession) userTable() string {
	return dynctx.table
}
