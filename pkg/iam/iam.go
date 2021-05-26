package iam

import (
	"go.uber.org/zap"
)

type AuthzProvider struct {
	dynamo       *dynamoSession
	cachedLogger *zap.Logger
}

func NewAuthzProvider() (*AuthzProvider, error) {
	d, err := newDynamoSession(nil)
	if err != nil {
		return nil, err
	}
	newSess := &AuthzProvider{
		dynamo: d,
	}

	return newSess, nil
}

func (a *AuthzProvider) Verify(id string) (bool, error) {
	log := a.logger().Sugar()
	defer log.Sync()

	user, err := a.dynamo.getUser(id)
	if err != nil {
		log.Warnf("Failed to fetch user <%s> for verification: %v", id, err)
		return false, err
	}

	if user == nil {
		log.Warnf("Verification: user <%s> not found.", id)
		return false, nil
	}

	log.Infof("user: %v", user)

	return true, nil
}

func (a *AuthzProvider) logger() *zap.Logger {
	if a.cachedLogger == nil {
		l, e := zap.NewDevelopment()
		if e == nil {
			a.cachedLogger = l
		}
	}
	return a.cachedLogger.WithOptions(zap.WithCaller(true), zap.AddStacktrace(zap.PanicLevel))
}
