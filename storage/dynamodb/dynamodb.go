package dynamodb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/storage"
	"gopkg.in/square/go-jose.v2"
)

const (
	clientKey         = "dex-client"
	authCodeKey       = "dex-authcode"
	refreshTokenKey   = "dex-refreshtoken"
	authRequestKey    = "dex-authreq"
	passwordKey       = "dex-password"
	offlineSessionKey = "dex-offlinesession"
	connectorKey      = "dex-connector"
	keysName          = "dex-openid-connect-keys"
	contentTypeKey    = "pk"
	idKey             = "sk"
)

type conn struct {
	db     *dynamodb.Client
	table  string
	logger log.Logger
}

func toStorageKey(key Keys) storage.Keys {
	var storageKey storage.Keys

	var signingKey jose.JSONWebKey
	signingKey.UnmarshalJSON(key.SigningKey)
	var signingKeyPub jose.JSONWebKey
	signingKeyPub.UnmarshalJSON(key.SigningKeyPub)

	storageKey.SigningKey = &signingKey
	storageKey.SigningKeyPub = &signingKeyPub
	storageKey.NextRotation = key.NextRotation
	storageKey.VerificationKeys = make([]storage.VerificationKey, len(key.VerificationKeys))

	for i, v := range key.VerificationKeys {
		storageKey.VerificationKeys[i].Expiry = v.Expiry
		var tempKey jose.JSONWebKey
		tempKey.UnmarshalJSON(v.Key)
		storageKey.VerificationKeys[i].PublicKey = &tempKey
	}

	return storageKey
}

func toDynamoKey(storageKey storage.Keys) Keys {
	signingKeyBytes, _ := storageKey.SigningKey.MarshalJSON()
	signingKeyPubBytes, _ := storageKey.SigningKeyPub.MarshalJSON()

	verificationKeys := make([]VerificationKey, len(storageKey.VerificationKeys))

	for i, v := range storageKey.VerificationKeys {
		pbBytes, _ := v.PublicKey.MarshalJSON()
		verificationKeys[i] = VerificationKey{
			Key:    pbBytes,
			Expiry: v.Expiry,
		}
	}

	return Keys{
		ContentType:      keysName,
		ID:               keysName,
		SigningKey:       signingKeyBytes,
		SigningKeyPub:    signingKeyPubBytes,
		VerificationKeys: verificationKeys,
		NextRotation:     storageKey.NextRotation,
	}
}

func (c *conn) Close() error {
	return nil
}

func (c *conn) putItem(data map[string]types.AttributeValue) error {
	input := &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item:      data,
	}
	_, err := c.db.PutItem(context.TODO(), input)

	if err != nil {
		return fmt.Errorf("putting item in dynamodb: %v", err)
	} else {
		return nil
	}
}

func (c *conn) getItem(content_type string, id string) (*dynamodb.GetItemOutput, error) {
	resp, err := c.db.GetItem(context.TODO(), &dynamodb.GetItemInput{
		Key: map[string]types.AttributeValue{
			contentTypeKey: &types.AttributeValueMemberS{Value: content_type},
			idKey:          &types.AttributeValueMemberS{Value: id},
		},
		TableName: aws.String(c.table)},
	)
	if err != nil {
		return resp, fmt.Errorf("getting item from dynamodb: %v", err)
	} else {
		return resp, nil
	}
}

func (c *conn) deleteItem(content_type string, id string) error {
	_, err := c.db.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
		Key: map[string]types.AttributeValue{
			contentTypeKey: &types.AttributeValueMemberS{Value: content_type},
			idKey:          &types.AttributeValueMemberS{Value: id},
		},
		TableName: aws.String(c.table),
	})

	if err != nil {
		return fmt.Errorf("deleting item in dynamodb: %v", err)
	} else {
		return nil
	}
}

func (c *conn) updateItem(contentType string, id string, expr expression.Expression) error {
	_, err := c.db.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			contentTypeKey: &types.AttributeValueMemberS{Value: contentType},
			idKey:          &types.AttributeValueMemberS{Value: id},
		},
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		UpdateExpression:          expr.Update(),
		ReturnValues:              types.ReturnValueUpdatedNew,
	})

	return err
}

func (c *conn) getItemsWithContentType(content_type string) ([]map[string]types.AttributeValue, error) {
	keyEx := expression.Key(contentTypeKey).Equal(expression.Value(content_type))
	expr, err := expression.NewBuilder().WithKeyCondition(keyEx).Build()

	if err != nil {
		return nil, fmt.Errorf("failed building query: %v", err)
	}

	queryInput := dynamodb.QueryInput{
		TableName:                 aws.String(c.table),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
	}

	resp, err := c.db.Query(context.TODO(), &queryInput)

	if err != nil {
		return nil, fmt.Errorf("query to dynamodb failed: %v", err)
	}

	return resp.Items, nil
}

func (c *conn) CreateAuthRequest(a storage.AuthRequest) error {
	var ttl = a.Expiry.Unix()
	authRequestDbd := AuthRequest{
		Request:     a,
		TTL:         ttl,
		ContentType: authRequestKey,
		ID:          a.ID,
	}

	authRequestData, err := attributevalue.MarshalMap(authRequestDbd)
	if err != nil {
		return err
	}

	return c.putItem(authRequestData)
}

func (c *conn) CreateClient(cli storage.Client) error {
	clientDbd := Client{
		Client:      cli,
		ContentType: clientKey,
		ID:          cli.ID,
	}

	clientData, err := attributevalue.MarshalMap(clientDbd)
	if err != nil {
		return err
	}

	return c.putItem(clientData)
}

func (c *conn) CreateAuthCode(code storage.AuthCode) error {
	ttl := code.Expiry.Unix()
	codeDbd := AuthCode{
		AuthCode:    code,
		ContentType: authCodeKey,
		TTL:         ttl,
		ID:          code.ID,
	}

	clientData, err := attributevalue.MarshalMap(codeDbd)
	if err != nil {
		return err
	}

	return c.putItem(clientData)
}

func (c *conn) CreateRefresh(r storage.RefreshToken) error {
	refreshDbd := RefreshToken{
		Token:       r,
		ContentType: refreshTokenKey,
		ID:          r.ID,
	}

	refreshTokenData, err := attributevalue.MarshalMap(refreshDbd)
	if err != nil {
		return err
	}

	return c.putItem(refreshTokenData)
}

func (c *conn) CreatePassword(p storage.Password) error {
	passwordDbd := Password{
		Password:    p,
		ContentType: passwordKey,
		ID:          strings.ToLower(p.Email),
	}

	passwordData, err := attributevalue.MarshalMap(passwordDbd)
	if err != nil {
		return err
	}

	return c.putItem(passwordData)
}

func (c *conn) CreateOfflineSessions(s storage.OfflineSessions) error {
	offlineSessionDbd := OfflineSessions{
		Session:     s,
		ContentType: offlineSessionKey,
		ID:          s.UserID + "-" + s.ConnID,
	}

	offlineSessionData, err := attributevalue.MarshalMap(offlineSessionDbd)
	if err != nil {
		return err
	}

	return c.putItem(offlineSessionData)
}

func (c *conn) CreateConnector(con storage.Connector) error {
	connectorDbd := Connector{
		Connector:   con,
		ContentType: connectorKey,
		ID:          con.ID,
	}

	connectorData, err := attributevalue.MarshalMap(connectorDbd)
	if err != nil {
		return err
	}

	return c.putItem(connectorData)
}

func (c *conn) GetAuthRequest(id string) (storage.AuthRequest, error) {
	resp, err := c.getItem(authRequestKey, id)

	if err != nil {
		return storage.AuthRequest{}, err
	}

	var authRequestDbd AuthRequest
	err = attributevalue.UnmarshalMap(resp.Item, &authRequestDbd)
	if err != nil {
		return storage.AuthRequest{}, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	return authRequestDbd.Request, nil
}

func (c *conn) GetAuthCode(id string) (storage.AuthCode, error) {
	resp, err := c.getItem(authCodeKey, id)

	if err != nil {
		return storage.AuthCode{}, err
	}

	var authCodeDbd AuthCode
	err = attributevalue.UnmarshalMap(resp.Item, &authCodeDbd)

	if err != nil {
		return storage.AuthCode{}, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	return authCodeDbd.AuthCode, nil
}

func (c *conn) GetClient(id string) (storage.Client, error) {
	resp, err := c.getItem(clientKey, id)

	if err != nil {
		return storage.Client{}, err
	}

	var clientDbd Client
	err = attributevalue.UnmarshalMap(resp.Item, &clientDbd)

	if err != nil {
		return storage.Client{}, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	return clientDbd.Client, nil
}

func (c *conn) GetKeys() (storage.Keys, error) {
	keyDbd := keysName
	resp, err := c.db.GetItem(context.TODO(), &dynamodb.GetItemInput{
		Key: map[string]types.AttributeValue{
			contentTypeKey: &types.AttributeValueMemberS{Value: keyDbd},
			idKey:          &types.AttributeValueMemberS{Value: keyDbd},
		},
		TableName: aws.String(c.table)},
	)

	if err != nil {
		return storage.Keys{}, err
	}

	var keyResp Keys
	err = attributevalue.UnmarshalMap(resp.Item, &keyResp)
	if err != nil {
		return storage.Keys{}, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	storageKey := toStorageKey(keyResp)

	if err != nil {
		return storage.Keys{}, err
	}

	return storageKey, err
}

func (c *conn) GetRefresh(id string) (storage.RefreshToken, error) {
	resp, err := c.getItem(refreshTokenKey, id)

	if err != nil {
		return storage.RefreshToken{}, err
	}

	var refreshDbd RefreshToken
	err = attributevalue.UnmarshalMap(resp.Item, &refreshDbd)

	if err != nil {
		return storage.RefreshToken{}, fmt.Errorf("dynamodb error failed: %v", err)
	}

	return refreshDbd.Token, nil
}

func (c *conn) GetPassword(email string) (storage.Password, error) {
	resp, err := c.getItem(passwordKey, strings.ToLower(email))

	if err != nil {
		return storage.Password{}, err
	}

	var passwordDbd Password
	err = attributevalue.UnmarshalMap(resp.Item, &passwordDbd)

	if err != nil {
		return storage.Password{}, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	return passwordDbd.Password, nil
}

func (c *conn) GetOfflineSessions(userID string, connID string) (storage.OfflineSessions, error) {
	resp, err := c.getItem(offlineSessionKey, userID+"-"+connID)

	if err != nil {
		return storage.OfflineSessions{}, err
	}

	var offlineSessionDbd OfflineSessions
	err = attributevalue.UnmarshalMap(resp.Item, &offlineSessionDbd)

	if err != nil {
		return storage.OfflineSessions{}, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	return offlineSessionDbd.Session, nil
}

func (c *conn) GetConnector(id string) (storage.Connector, error) {
	resp, err := c.getItem(connectorKey, id)

	if err != nil {
		return storage.Connector{}, err
	}

	var connectorDbd Connector
	err = attributevalue.UnmarshalMap(resp.Item, &connectorDbd)

	if err != nil {
		return storage.Connector{}, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	return connectorDbd.Connector, nil
}

func (c *conn) GetDeviceRequest(userCode string) (storage.DeviceRequest, error) {
	return storage.DeviceRequest{
		UserCode:     "",
		DeviceCode:   "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       nil,
		Expiry:       time.Time{},
	}, nil
}

func (c *conn) GetDeviceToken(deviceCode string) (storage.DeviceToken, error) {
	return storage.DeviceToken{
		DeviceCode:          "",
		Status:              "",
		Token:               "",
		Expiry:              time.Time{},
		LastRequestTime:     time.Time{},
		PollIntervalSeconds: 0,
		PKCE:                storage.PKCE{},
	}, nil
}

func (c *conn) ListClients() ([]storage.Client, error) {
	clientsResp, err := c.getItemsWithContentType(clientKey)

	if err != nil {
		return nil, err
	}

	var clientsDbd []Client
	err = attributevalue.UnmarshalListOfMaps(clientsResp, &clientsDbd)
	if err != nil {
		return nil, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	clients := make([]storage.Client, len(clientsDbd))
	for i, v := range clientsDbd {
		clients[i] = v.Client
	}

	return clients, nil
}

func (c *conn) ListRefreshTokens() ([]storage.RefreshToken, error) {
	tokenResp, err := c.getItemsWithContentType(refreshTokenKey)

	if err != nil {
		return nil, err
	}

	var tokensDbd []RefreshToken
	err = attributevalue.UnmarshalListOfMaps(tokenResp, &tokensDbd)
	if err != nil {
		return nil, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	tokens := make([]storage.RefreshToken, len(tokensDbd))
	for i, v := range tokensDbd {
		tokens[i] = v.Token
	}

	return tokens, nil
}

func (c *conn) ListPasswords() ([]storage.Password, error) {
	passwordsResp, err := c.getItemsWithContentType(passwordKey)

	if err != nil {
		return nil, err
	}

	var passwordsDbd []Password
	err = attributevalue.UnmarshalListOfMaps(passwordsResp, &passwordsDbd)
	if err != nil {
		return nil, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	passwords := make([]storage.Password, len(passwordsDbd))
	for i, v := range passwordsDbd {
		passwords[i] = v.Password
	}

	return passwords, nil
}

func (c *conn) ListConnectors() ([]storage.Connector, error) {
	connectorResp, err := c.getItemsWithContentType(connectorKey)

	if err != nil {
		return nil, err
	}

	var connectorsDbd []Connector
	err = attributevalue.UnmarshalListOfMaps(connectorResp, &connectorsDbd)
	if err != nil {
		return nil, fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	connectors := make([]storage.Connector, len(connectorsDbd))
	for i, v := range connectorsDbd {
		connectors[i] = v.Connector
	}

	return connectors, nil
}

func (c *conn) DeleteAuthRequest(id string) error { return c.deleteItem(authRequestKey, id) }

func (c *conn) DeleteAuthCode(code string) error { return c.deleteItem(authCodeKey, code) }

func (c *conn) DeleteClient(id string) error { return c.deleteItem(clientKey, id) }

func (c *conn) DeleteRefresh(id string) error { return c.deleteItem(refreshTokenKey, id) }

func (c *conn) DeletePassword(email string) error {
	return c.deleteItem(passwordKey, strings.ToLower(email))
}

func (c *conn) DeleteOfflineSessions(userID string, connID string) error {
	return c.deleteItem(offlineSessionKey, userID+"-"+connID)
}

func (c *conn) DeleteConnector(id string) error { return c.deleteItem(connectorKey, id) }

func (c *conn) UpdateClient(id string, updater func(old storage.Client) (storage.Client, error)) error {
	resp, err := c.getItem(clientKey, id)
	if err != nil {
		return err
	}

	var client Client
	err = attributevalue.UnmarshalMap(resp.Item, &client)
	if err != nil {
		return fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	newClient, err := updater(client.Client)
	if err != nil {
		return err
	}

	update := expression.Set(expression.Name("client"), expression.Value(newClient))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		return err
	} else {
		c.updateItem(clientKey, id, expr)
		return nil
	}
}

func (c *conn) UpdateKeys(updater func(old storage.Keys) (storage.Keys, error)) error {
	getInput := dynamodb.GetItemInput{
		Key: map[string]types.AttributeValue{
			idKey:          &types.AttributeValueMemberS{Value: keysName},
			contentTypeKey: &types.AttributeValueMemberS{Value: keysName},
		},
		TableName: aws.String(c.table),
	}

	resp, err := c.db.GetItem(context.TODO(), &getInput)
	if err != nil {
		return err
	}

	var keys storage.Keys
	if resp.Item != nil {
		var dynamoKey Keys
		if err = attributevalue.UnmarshalMap(resp.Item, &dynamoKey); err != nil {
			return fmt.Errorf("dynamodb unmarshal failed: %v", err)
		}
		keys = toStorageKey(dynamoKey)
	} else {
		keys = storage.Keys{}
	}

	nc, err := updater(keys)
	if err != nil {
		return err
	}

	updatedKey := toDynamoKey(nc)

	if resp.Item != nil {
		update := expression.Set(expression.Name("signing_key"), expression.Value(updatedKey.SigningKey))
		update.Set(expression.Name("signing_key_pub"), expression.Value(updatedKey.SigningKeyPub))
		update.Set(expression.Name("verification_keys"), expression.Value(updatedKey.VerificationKeys))
		update.Set(expression.Name("next_rotation"), expression.Value(updatedKey.NextRotation))
		expr, err := expression.NewBuilder().WithUpdate(update).Build()

		if err != nil {
			return err
		} else {
			return c.updateItem(keysName, keysName, expr)
		}
	} else {
		updateKeyAttrs, err := attributevalue.MarshalMap(updatedKey)
		if err != nil {
			return err
		} else {
			return c.putItem(updateKeyAttrs)
		}
	}
}

func (c *conn) UpdateAuthRequest(id string, updater func(a storage.AuthRequest) (storage.AuthRequest, error)) error {
	resp, err := c.getItem(authRequestKey, id)
	if err != nil {
		return err
	}

	var authCurrent AuthRequest
	err = attributevalue.UnmarshalMap(resp.Item, &authCurrent)
	if err != nil {
		return fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	newAuth, err := updater(authCurrent.Request)
	if err != nil {
		return err
	}

	update := expression.Set(expression.Name("request"), expression.Value(newAuth))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		return err
	} else {
		return c.updateItem(authRequestKey, id, expr)
	}
}

func (c *conn) UpdateRefreshToken(id string, updater func(r storage.RefreshToken) (storage.RefreshToken, error)) error {
	resp, err := c.getItem(refreshTokenKey, id)
	if err != nil {
		return err
	}

	var refreshToken RefreshToken
	err = attributevalue.UnmarshalMap(resp.Item, &refreshToken)
	if err != nil {
		return fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	newRefreshToken, err := updater(refreshToken.Token)
	if err != nil {
		return err
	}

	update := expression.Set(expression.Name("token"), expression.Value(newRefreshToken))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		return err
	} else {
		return c.updateItem(refreshTokenKey, id, expr)
	}
}

func (c *conn) UpdatePassword(email string, updater func(p storage.Password) (storage.Password, error)) error {
	resp, err := c.getItem(passwordKey, email)
	if err != nil {
		return err
	}

	var password Password
	err = attributevalue.UnmarshalMap(resp.Item, &password)
	if err != nil {
		return fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	newPassword, err := updater(password.Password)
	if err != nil {
		return err
	}

	update := expression.Set(expression.Name("password"), expression.Value(newPassword))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		return err
	} else {
		return c.updateItem(passwordKey, email, expr)
	}
}

func (c *conn) UpdateOfflineSessions(userID string, connID string, updater func(s storage.OfflineSessions) (storage.OfflineSessions, error)) error {
	id := userID + "-" + connID
	resp, err := c.getItem(passwordKey, id)
	if err != nil {
		return err
	}

	var offlineSession OfflineSessions
	err = attributevalue.UnmarshalMap(resp.Item, &offlineSession)
	if err != nil {
		return fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	newSession, err := updater(offlineSession.Session)
	if err != nil {
		return err
	}

	update := expression.Set(expression.Name("session"), expression.Value(newSession))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		return err
	} else {
		return c.updateItem(offlineSessionKey, id, expr)
	}
}

func (c *conn) UpdateConnector(id string, updater func(c storage.Connector) (storage.Connector, error)) error {
	resp, err := c.getItem(passwordKey, id)
	if err != nil {
		return err
	}

	var connector Connector
	err = attributevalue.UnmarshalMap(resp.Item, &connector)
	if err != nil {
		return fmt.Errorf("dynamodb unmarshal failed: %v", err)
	}

	newConnector, err := updater(connector.Connector)
	if err != nil {
		return err
	}

	update := expression.Set(expression.Name("connector"), expression.Value(newConnector))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		return err
	} else {
		return c.updateItem(connectorKey, id, expr)
	}
}

func (c *conn) GarbageCollect(now time.Time) (storage.GCResult, error) {
	return storage.GCResult{}, nil
}

func (c *conn) CreateDeviceRequest(d storage.DeviceRequest) error { return nil }

func (c *conn) CreateDeviceToken(d storage.DeviceToken) error { return nil }

func (c *conn) UpdateDeviceToken(deviceCode string, updater func(t storage.DeviceToken) (storage.DeviceToken, error)) error {
	return nil
}
