package dynamodb

import (
	"time"

	"github.com/dexidp/dex/storage"
)

type Client struct {
	Client      storage.Client
	ContentType string
	ID          string
}

type AuthCode struct {
	AuthCode    storage.AuthCode
	TTL         int64
	ContentType string
	ID          string
}

type RefreshToken struct {
	Token       storage.RefreshToken
	ContentType string
	ID          string
}

type AuthRequest struct {
	Request     storage.AuthRequest
	TTL         int64
	ContentType string
	ID          string
}

type Password struct {
	Password    storage.Password
	ContentType string
	ID          string
}

type OfflineSessions struct {
	Session     storage.OfflineSessions
	ContentType string
	ID          string
}

type Connector struct {
	Connector   storage.Connector
	ContentType string
	ID          string
}

type Keys struct {
	SigningKey       []byte
	SigningKeyPub    []byte
	VerificationKeys []VerificationKey
	NextRotation     time.Time
	ContentType      string
	ID               string
}

type VerificationKey struct {
	Key    []byte
	Expiry time.Time
}
