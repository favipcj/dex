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
)

type conn struct {
	db     *dynamodb.Client
	table  string
	logger log.Logger
}

func keyID(prefix string, id string) string { return prefix + "-" + id }
func keySession(prefix string, id string, connId string) string {
	return prefix + "-" + strings.ToLower(id+"-"+connId)
}

func (c *conn) Close() error {
	return nil
}

func (c *conn) putItem(data map[string]types.AttributeValue) {
	input := &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item:      data,
	}

	_, err := c.db.PutItem(context.TODO(), input)

	if err != nil {
		c.logger.Infof("Error in putitem: %v\n", err)
	}
}

func (c *conn) getItem(content_type string, id string) (*dynamodb.GetItemOutput, error) {
	return c.db.GetItem(context.TODO(), &dynamodb.GetItemInput{
		Key: map[string]types.AttributeValue{
			"ContentType": &types.AttributeValueMemberS{Value: content_type},
			"ID":          &types.AttributeValueMemberS{Value: id},
		},
		TableName: aws.String(c.table)},
	)
}

func (c *conn) deleteItem(content_type string, id string) error {
	c.logger.Infof("Deleting item (ID: %v, ContentType: %v)\n", id, content_type)

	_, err := c.db.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
		Key: map[string]types.AttributeValue{
			"ContentType": &types.AttributeValueMemberS{Value: content_type},
			"ID":          &types.AttributeValueMemberS{Value: id},
		},
		TableName: aws.String(c.table),
	})

	return err
}

func (c *conn) updateItem(contentType string, id string, expr expression.Expression) {
	_, err := c.db.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"ContentType": &types.AttributeValueMemberS{Value: contentType},
			"ID":          &types.AttributeValueMemberS{Value: id},
		},
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		UpdateExpression:          expr.Update(),
		ReturnValues:              types.ReturnValueUpdatedNew,
	})

	if err != nil {
		c.logger.Infof("Could not update %v: %v: %v", contentType, id, err)
	}
}

func (c *conn) CreateAuthRequest(a storage.AuthRequest) error {
	var ttl = uint32(time.Until(a.Expiry).Seconds())
	authRequestDbd := AuthRequest{
		Request:     a,
		TTL:         ttl,
		ContentType: authRequestKey,
		ID:          a.ID,
	}

	authRequestData, e := attributevalue.MarshalMap(authRequestDbd)
	if e != nil {
		c.logger.Infof("%v\n", e)
	}

	c.putItem(authRequestData)

	return nil
}

func (c *conn) CreateClient(cli storage.Client) error {
	clientDbd := Client{
		Client:      cli,
		ContentType: clientKey,
		ID:          cli.ID,
	}

	clientData, _ := attributevalue.MarshalMap(clientDbd)
	c.putItem(clientData)

	return nil
}

func (c *conn) CreateAuthCode(code storage.AuthCode) error {
	ttl := uint32(time.Until(code.Expiry).Seconds())
	codeDbd := AuthCode{
		AuthCode:    code,
		ContentType: authCodeKey,
		TTL:         ttl,
		ID:          code.ID,
	}

	clientData, _ := attributevalue.MarshalMap(codeDbd)
	c.putItem(clientData)

	return nil
}

func (c *conn) CreateRefresh(r storage.RefreshToken) error {
	refreshDbd := RefreshToken{
		Token:       r,
		ContentType: refreshTokenKey,
		ID:          r.ID,
	}

	tokenData, _ := attributevalue.MarshalMap(refreshDbd)
	c.putItem(tokenData)

	return nil
}

func (c *conn) CreatePassword(p storage.Password) error {
	passwordDbd := Password{
		Password:    p,
		ContentType: passwordKey,
		ID:          strings.ToLower(p.Email),
	}

	passwordData, _ := attributevalue.MarshalMap(passwordDbd)
	c.putItem(passwordData)

	return nil
}

func (c *conn) CreateOfflineSessions(s storage.OfflineSessions) error {
	offlineSessionDbd := OfflineSessions{
		Session:     s,
		ContentType: offlineSessionKey,
		ID:          s.UserID + "-" + s.ConnID,
	}

	offlineSessionData, _ := attributevalue.MarshalMap(offlineSessionDbd)
	c.putItem(offlineSessionData)

	return nil
}

func (c *conn) CreateConnector(con storage.Connector) error {
	connectorDbd := Connector{
		Connector:   con,
		ContentType: connectorKey,
		ID:          con.ID,
	}

	connectorData, _ := attributevalue.MarshalMap(connectorDbd)
	c.putItem(connectorData)

	return nil
}

func (c *conn) GetAuthRequest(id string) (storage.AuthRequest, error) {
	var temp storage.AuthRequest

	resp, err := c.getItem(authRequestKey, id)

	if err != nil {
		return temp, err
	}

	var authRequestDbd AuthRequest
	err = attributevalue.UnmarshalMap(resp.Item, &authRequestDbd)

	if err != nil {
		return temp, err
	}

	temp = authRequestDbd.Request

	return temp, nil
}

func (c *conn) GetAuthCode(id string) (storage.AuthCode, error) {
	var temp storage.AuthCode
	resp, err := c.getItem(authCodeKey, id)

	if err != nil {
		return temp, err
	}

	var authCodeDbd AuthCode
	err = attributevalue.UnmarshalMap(resp.Item, &authCodeDbd)

	if err != nil {
		return temp, err
	}

	temp = authCodeDbd.AuthCode

	return temp, nil
}

func (c *conn) GetClient(id string) (storage.Client, error) {
	var temp storage.Client
	resp, err := c.getItem(clientKey, id)

	if err != nil {
		return temp, err
	}

	var clientDbd Client
	err = attributevalue.UnmarshalMap(resp.Item, &clientDbd)

	if err != nil {
		return temp, err
	}

	temp = clientDbd.Client

	return temp, nil
}

func (c *conn) GetKeys() (storage.Keys, error) {
	var keys storage.Keys
	keyDbd := keysName
	resp, err := c.db.GetItem(context.TODO(), &dynamodb.GetItemInput{
		Key: map[string]types.AttributeValue{
			"ContentType": &types.AttributeValueMemberS{Value: keyDbd},
			"ID":          &types.AttributeValueMemberS{Value: keyDbd},
		},
		TableName: aws.String(c.table)},
	)

	if err != nil {
		c.logger.Infof("%v\n", err)
		return keys, fmt.Errorf("%v", err)
	}

	var keyResp Keys
	err = attributevalue.UnmarshalMap(resp.Item, &keyResp)

	var signingKey jose.JSONWebKey
	signingKey.UnmarshalJSON(keyResp.SigningKey)
	var signingKeyPub jose.JSONWebKey
	signingKeyPub.UnmarshalJSON(keyResp.SigningKeyPub)

	keys.SigningKey = &signingKey
	keys.SigningKeyPub = &signingKeyPub
	keys.VerificationKeys = keyResp.VerificationKeys
	keys.NextRotation = keyResp.NextRotation

	if err != nil {
		c.logger.Infof("%v\n", err)
	}

	return keys, err
}

func (c *conn) GetRefresh(id string) (storage.RefreshToken, error) {
	var temp storage.RefreshToken
	resp, err := c.getItem(refreshTokenKey, id)

	if err != nil {
		return temp, err
	}

	var refreshDbd RefreshToken
	err = attributevalue.UnmarshalMap(resp.Item, &refreshDbd)

	if err != nil {
		return temp, err
	}

	temp = refreshDbd.Token
	return temp, nil
}

func (c *conn) GetPassword(email string) (storage.Password, error) {
	var temp storage.Password
	resp, err := c.getItem(passwordKey, strings.ToLower(email))

	if err != nil {
		return temp, err
	}

	var passwordDbd Password
	err = attributevalue.UnmarshalMap(resp.Item, &passwordDbd)

	if err != nil {
		return temp, err
	}

	temp = passwordDbd.Password
	return temp, nil
}

func (c *conn) GetOfflineSessions(userID string, connID string) (storage.OfflineSessions, error) {
	var temp storage.OfflineSessions
	resp, err := c.getItem(offlineSessionKey, userID+"-"+connID)

	if err != nil {
		return temp, err
	}

	var offlineSessionDbd OfflineSessions
	err = attributevalue.UnmarshalMap(resp.Item, &offlineSessionDbd)

	if err != nil {
		return temp, err
	}

	temp = offlineSessionDbd.Session
	return temp, nil
}

func (c *conn) GetConnector(id string) (storage.Connector, error) {
	var temp storage.Connector
	resp, err := c.getItem(connectorKey, id)

	if err != nil {
		return temp, err
	}

	var connectorDbd Connector
	err = attributevalue.UnmarshalMap(resp.Item, &connectorDbd)

	if err != nil {
		return temp, err
	}

	temp = connectorDbd.Connector
	return temp, nil
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

func (c *conn) getItemsWithKeyPrefix(content_type string) ([]map[string]types.AttributeValue, error) {
	keyEx := expression.Key("ContentType").Equal(expression.Value(content_type))
	expr, _ := expression.NewBuilder().WithKeyCondition(keyEx).Build()
	queryInput := dynamodb.QueryInput{
		TableName:                 aws.String(c.table),
		IndexName:                 aws.String("ContentType-index"),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
	}

	resp, err := c.db.Query(context.TODO(), &queryInput)

	if err != nil {
		return nil, err
	}

	return resp.Items, nil
}

func (c *conn) ListClients() ([]storage.Client, error) {
	var clientsDbd []Client
	var err error

	clientsResp, err := c.getItemsWithKeyPrefix(clientKey)

	if err != nil {
		c.logger.Infof("Could not list clients: %v\n", err)
		return nil, err
	}

	err = attributevalue.UnmarshalListOfMaps(clientsResp, &clientsDbd)
	if err != nil {
		c.logger.Infof("Could not unmarshall list of clients: %v\n", err)
		return nil, err
	}

	clients := make([]storage.Client, len(clientsDbd))
	for i, v := range clientsDbd {
		clients[i] = v.Client
	}

	return clients, nil
}

func (c *conn) ListRefreshTokens() ([]storage.RefreshToken, error) {
	var tokensDbd []RefreshToken
	var err error

	tokenResp, err := c.getItemsWithKeyPrefix(refreshTokenKey)

	if err != nil {
		c.logger.Infof("Could not list refresh tokens: %v\n", err)
		return nil, err
	}

	err = attributevalue.UnmarshalListOfMaps(tokenResp, &tokensDbd)
	if err != nil {
		c.logger.Infof("Could not unmarshall list of refresh tokens: %v\n", err)
		return nil, err
	}

	tokens := make([]storage.RefreshToken, len(tokensDbd))
	for i, v := range tokensDbd {
		tokens[i] = v.Token
	}

	return tokens, nil
}

func (c *conn) ListPasswords() ([]storage.Password, error) {
	var passwordsDbd []Password
	var err error

	passwordsResp, err := c.getItemsWithKeyPrefix(passwordKey)

	if err != nil {
		c.logger.Infof("Could not list passwords: %v\n", err)
		return nil, err
	}

	err = attributevalue.UnmarshalListOfMaps(passwordsResp, &passwordsDbd)
	if err != nil {
		c.logger.Infof("Could not unmarshall list of passwords: %v\n", err)
		return nil, err
	}

	passwords := make([]storage.Password, len(passwordsDbd))
	for i, v := range passwordsDbd {
		passwords[i] = v.Password
	}

	return passwords, nil
}

func (c *conn) ListConnectors() ([]storage.Connector, error) {
	var connectorsDbd []Connector
	var err error

	connectorResp, err := c.getItemsWithKeyPrefix(connectorKey)

	if err != nil {
		c.logger.Infof("Could not list connectors: %v\n", err)
		return nil, err
	}

	err = attributevalue.UnmarshalListOfMaps(connectorResp, &connectorsDbd)
	if err != nil {
		c.logger.Infof("Could not unmarshall list of connectors: %v\n", err)
		return nil, err
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
	var client Client
	resp, _ := c.getItem(clientKey, id)
	_ = attributevalue.UnmarshalMap(resp.Item, &client)

	newClient, _ := updater(client.Client)
	update := expression.Set(expression.Name("Client"), expression.Value(newClient))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		c.logger.Infof("Couldn't build expression for update: %v", err)
	} else {
		c.updateItem(clientKey, id, expr)
	}

	return nil
}

func (c *conn) UpdateKeys(updater func(old storage.Keys) (storage.Keys, error)) error {
	getInput := dynamodb.GetItemInput{
		Key: map[string]types.AttributeValue{
			"ID":          &types.AttributeValueMemberS{Value: keysName},
			"ContentType": &types.AttributeValueMemberS{Value: keysName},
		},
		TableName: aws.String(c.table),
	}

	resp, err := c.db.GetItem(context.TODO(), &getInput)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	var item Keys
	err = attributevalue.UnmarshalMap(resp.Item, &item)
	var signingKey *jose.JSONWebKey
	signingKey.UnmarshalJSON(item.SigningKey)
	var signingKeyPub *jose.JSONWebKey
	signingKey.UnmarshalJSON(item.SigningKeyPub)
	keys := storage.Keys{
		SigningKey:       signingKey,
		SigningKeyPub:    signingKeyPub,
		NextRotation:     item.NextRotation,
		VerificationKeys: item.VerificationKeys,
	}

	if err != nil {
		return fmt.Errorf("%v", err)
	}

	nc, err := updater(keys)

	if err != nil {
		return fmt.Errorf("%v", err)
	}
	signingKeyBytes, _ := nc.SigningKey.MarshalJSON()
	signingKeyPubBytes, _ := nc.SigningKeyPub.MarshalJSON()

	new_key := Keys{
		ContentType:      keysName,
		ID:               keysName,
		SigningKey:       signingKeyBytes,
		SigningKeyPub:    signingKeyPubBytes,
		VerificationKeys: nc.VerificationKeys,
		NextRotation:     nc.NextRotation,
	}

	nc_map, _ := attributevalue.MarshalMap(new_key)

	input := &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item:      nc_map,
	}

	_, err = c.db.PutItem(context.TODO(), input)

	if err != nil {
		c.logger.Infof("Error in putitem: %v\n", err)
	}

	return nil
}

func (c *conn) UpdateAuthRequest(id string, updater func(a storage.AuthRequest) (storage.AuthRequest, error)) error {
	var authCurrent AuthRequest
	resp, _ := c.getItem(authRequestKey, id)
	_ = attributevalue.UnmarshalMap(resp.Item, &authCurrent)

	c.logger.Infof("Updating auth request: %v. Name: %v", id, authCurrent.Request.Claims.Username)

	newAuth, _ := updater(authCurrent.Request)
	c.logger.Infof("Update data for auth request: %v. Name: %v", newAuth.ID, newAuth.Claims.Username)
	update := expression.Set(expression.Name("Request"), expression.Value(newAuth))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		c.logger.Infof("Couldn't build expression for update: %v", err)
	} else {
		c.updateItem(authRequestKey, id, expr)
	}

	return nil
}

func (c *conn) UpdateRefreshToken(id string, updater func(r storage.RefreshToken) (storage.RefreshToken, error)) error {
	var refreshToken RefreshToken
	resp, _ := c.getItem(refreshTokenKey, id)
	_ = attributevalue.UnmarshalMap(resp.Item, &refreshToken)

	newRefreshToken, _ := updater(refreshToken.Token)
	update := expression.Set(expression.Name("Token"), expression.Value(newRefreshToken))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		c.logger.Infof("Couldn't build expression for update: %v", err)
	} else {
		c.updateItem(refreshTokenKey, id, expr)
	}

	return nil
}

func (c *conn) UpdatePassword(email string, updater func(p storage.Password) (storage.Password, error)) error {
	var password Password
	resp, _ := c.getItem(passwordKey, email)
	_ = attributevalue.UnmarshalMap(resp.Item, &password)

	newPassword, _ := updater(password.Password)
	update := expression.Set(expression.Name("Password"), expression.Value(newPassword))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		c.logger.Infof("Couldn't build expression for update: %v", err)
	} else {
		c.updateItem(passwordKey, email, expr)
	}

	return nil
}

func (c *conn) UpdateOfflineSessions(userID string, connID string, updater func(s storage.OfflineSessions) (storage.OfflineSessions, error)) error {
	var offlineSession OfflineSessions
	id := userID + "-" + connID
	resp, _ := c.getItem(passwordKey, id)
	_ = attributevalue.UnmarshalMap(resp.Item, &offlineSession)

	newSession, _ := updater(offlineSession.Session)
	update := expression.Set(expression.Name("Session"), expression.Value(newSession))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		c.logger.Infof("Couldn't build expression for update: %v", err)
	} else {
		c.updateItem(offlineSessionKey, id, expr)
	}

	return nil
}

func (c *conn) UpdateConnector(id string, updater func(c storage.Connector) (storage.Connector, error)) error {
	var connector Connector
	resp, _ := c.getItem(passwordKey, id)
	_ = attributevalue.UnmarshalMap(resp.Item, &connector)

	newConnector, _ := updater(connector.Connector)
	update := expression.Set(expression.Name("Connector"), expression.Value(newConnector))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()

	if err != nil {
		c.logger.Infof("Couldn't build expression for update: %v", err)
	} else {
		c.updateItem(connectorKey, id, expr)
	}

	return nil
}

func (c *conn) GarbageCollect(now time.Time) (storage.GCResult, error) {
	var temp storage.GCResult
	return temp, nil
}

func (c *conn) CreateDeviceRequest(d storage.DeviceRequest) error { return nil }

func (c *conn) CreateDeviceToken(d storage.DeviceToken) error { return nil }

func (c *conn) UpdateDeviceToken(deviceCode string, updater func(t storage.DeviceToken) (storage.DeviceToken, error)) error {
	return nil
}
