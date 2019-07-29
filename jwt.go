package gw

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/auth0/go-jwt-middleware"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/juju/errors"
	"io/ioutil"
	"net/http"
)

func SetupJWTMiddleware(private, public string) (*jwtmiddleware.JWTMiddleware, *rsa.PrivateKey, string, error) {
	signBytes, err := ioutil.ReadFile(private)
	if err != nil {
		return nil, nil, "", errors.Annotatef(err, "Failed to read RSA private key")
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return nil, nil, "", errors.Annotatef(err, "Failed to parse RSA private key file")
	}

	verifyBytes, err := ioutil.ReadFile(public)
	if err != nil {
		return nil, nil, "", errors.Annotatef(err, "Failed to read RSA public key")
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return nil, nil, "", errors.Annotatef(err, "Failed to parse RSA public key file")
	}

	jm := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
		},
		SigningMethod:       jwt.SigningMethodRS512,
		CredentialsOptional: false,
		EnableAuthOnOptions: true,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err string) {
			// Don't have middleware do anything with error other than return
			// it as it occurs
			return
		},
	})

	pubDER, err := x509.MarshalPKIXPublicKey(verifyKey)
	if err != nil {
		return nil, nil, "", errors.Annotatef(err, "PEMifying public key failed")
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	return jm, signKey, string(pubBytes), nil
}
