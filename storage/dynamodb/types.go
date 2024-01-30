package dynamodb

import (
	"time"

	"github.com/dexidp/dex/storage"
)

type Client struct {
	Client      storage.Client `dynamodbav:"client"`
	ContentType string         `dynamodbav:"pk"`
	ID          string         `dynamodbav:"sk"`
}

type AuthCode struct {
	AuthCode    storage.AuthCode `dynamodbav:"uth_code"`
	TTL         int64            `dynamodbav:"ttl"`
	ContentType string           `dynamodbav:"pk"`
	ID          string           `dynamodbav:"sk"`
}

type RefreshToken struct {
	Token       storage.RefreshToken `dynamodbav:"token"`
	ContentType string               `dynamodbav:"pk"`
	ID          string               `dynamodbav:"sk"`
}

type AuthRequest struct {
	Request     storage.AuthRequest `dynamodbav:"request"`
	TTL         int64               `dynamodbav:"ttl"`
	ContentType string              `dynamodbav:"pk"`
	ID          string              `dynamodbav:"sk"`
}

type Password struct {
	Password    storage.Password `dynamodbav:"password"`
	ContentType string           `dynamodbav:"pk"`
	ID          string           `dynamodbav:"sk"`
}

type OfflineSessions struct {
	Session     storage.OfflineSessions `dynamodbav:"session"`
	ContentType string                  `dynamodbav:"pk"`
	ID          string                  `dynamodbav:"sk"`
}

type Connector struct {
	Connector   storage.Connector `dynamodbav:"connector"`
	ContentType string            `dynamodbav:"pk"`
	ID          string            `dynamodbav:"sk"`
}

type Keys struct {
	SigningKey       []byte            `dynamodbav:"signing_key"`
	SigningKeyPub    []byte            `dynamodbav:"signing_key_pub"`
	VerificationKeys []VerificationKey `dynamodbav:"verification_keys"`
	NextRotation     time.Time         `dynamodbav:"next_rotation"`
	ContentType      string            `dynamodbav:"pk"`
	ID               string            `dynamodbav:"sk"`
}

type VerificationKey struct {
	Key    []byte    `dynamodbav:"key"`
	Expiry time.Time `dynamodbav:"expiry"`
}
