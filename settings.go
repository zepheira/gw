package gw

import (
	"crypto/rsa"
	"github.com/auth0/go-jwt-middleware"
	"github.com/oxtoacart/bpool"
	"html/template"
)

type Settings interface {
	GetLDAP() []LDAPConfiguration
	SetTemplates(map[string]*template.Template)
	GetTemplates() map[string]*template.Template
	GetPool() *bpool.BufferPool
	GetJWT() *jwtmiddleware.JWTMiddleware
	GetJWTSigningKey() *rsa.PrivateKey
	GetJWTPublicKey() string
	GetEvents() Events
	GetCORSOptions() *CORSOptions
}

type Events interface {
	OnLogin(*LDAPUser) error
}

type MockSettings struct {
}

func (s MockSettings) GetLDAP() []LDAPConfiguration {
	return nil
}

func (s MockSettings) SetTemplates(map[string]*template.Template) {
	return
}

func (s MockSettings) GetTemplates() map[string]*template.Template {
	return nil
}

func (s MockSettings) GetPool() *bpool.BufferPool {
	return nil
}

func (s MockSettings) GetJWT() *jwtmiddleware.JWTMiddleware {
	return nil
}

func (s MockSettings) GetJWTSigningKey() *rsa.PrivateKey {
	return nil
}

func (s MockSettings) GetJWTPublicKey() string {
	return ""
}

func (s MockSettings) GetEvents() Events {
	return nil
}

func (s MockSettings) GetCORSOptions() *CORSOptions {
	return nil
}
