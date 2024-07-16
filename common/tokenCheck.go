package common

import (
	"fmt"
	"time"

	"github.com/OpsMx/ssd-jwt-auth/ssdjwtauth"
)

func CheckToken(dgraphToken string) error {
	claims, err := TokenVerifier.VerifyToken(dgraphToken)
	if err != nil {
		return fmt.Errorf("unauthorized token")
	}

	if claims.SSDCLaims.Type != ssdjwtauth.SSDTokenTypeInternal {
		return fmt.Errorf("token is not of type internal")
	}

	if claims.ExpiresAt.Time.Before(time.Now().Add(1 * time.Hour)) {
		return fmt.Errorf("token will expire within an hour. Please ensure token has validity of atleast an hour before we begin upgradation process")
	}

	return nil

}
