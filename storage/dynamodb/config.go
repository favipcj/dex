package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/storage"
)

type AWSConfig struct {
	ProfileName string
	Region      string
	Table       string
}

type DynamoDB struct {
	AWSConfig
}

func (dbd *DynamoDB) Open(logger log.Logger) (storage.Storage, error) {
	conn, err := dbd.open(logger)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (dbd *DynamoDB) open(logger log.Logger) (*conn, error) {
	var cfg aws.Config

	if dbd.ProfileName != "" {
		var err error
		cfg, err = config.LoadDefaultConfig(
			context.TODO(),
			config.WithRegion(dbd.Region),
			config.WithSharedConfigProfile(dbd.ProfileName),
		)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		cfg, err = config.LoadDefaultConfig(
			context.TODO(),
			config.WithRegion(dbd.Region),
		)
		if err != nil {
			return nil, err
		}
	}

	svc := dynamodb.NewFromConfig(cfg)

	c := &conn{
		db:     svc,
		logger: logger,
		table:  dbd.Table,
	}

	return c, nil
}
