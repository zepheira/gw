package gw

import (
	"context"
	"encoding/json"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/juju/errors"
	"io"
	"net/http"
	"time"
)

// Middleware to mark a resource as one requiring authentication to access
func Auth(fn AppHandler) AppHandler {
	return func(w http.ResponseWriter, r *http.Request) *AppError {
		env := r.Context().Value("env").(Settings)
		err := env.GetJWT().CheckJWT(w, r)
		if err != nil {
			return &AppError{http.StatusForbidden, nil}
		}
		return fn(w, r)
	}
}

// Middleware to mark a resource as granting greater access when authenticated,
// but authentication not required for limited access.
func PartialAuth(fn AppHandler) AppHandler {
	return func(w http.ResponseWriter, r *http.Request) *AppError {
		env := r.Context().Value("env").(Settings)
		err := env.GetJWT().CheckJWT(w, r)
		if err != nil {
			r = r.WithContext(context.WithValue(r.Context(), env.GetJWT().Options.UserProperty, &jwt.Token{
				Claims: jwt.MapClaims{
					"username":        "",
					"unauthenticated": true,
				},
			}))
		}
		return fn(w, r)
	}
}

func NotAuth(token *jwt.Token) bool {
	_, unauth := token.Claims.(jwt.MapClaims)["unauthenticated"]
	return unauth
}

func AuthHandlersRegister(router *mux.Router, c Settings) {
	router.Handle("/api/auth/login",
		Middleware(LoginHandler, c)).
		Methods("POST")

	router.Handle("/api/auth/logout",
		Middleware(Auth(LogoutHandler), c)).
		Methods("POST")

	router.Handle("/api/auth/refresh",
		Middleware(Auth(RefreshHandler), c)).
		Methods("POST")
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func UsernameFromToken(token *jwt.Token) string {
	username, ok := token.Claims.(jwt.MapClaims)["username"].(string)
	if !ok {
		return ""
	}

	return username
}

// Takes login info and returns a JWT if successful, 403 if not
func LoginHandler(w http.ResponseWriter, r *http.Request) *AppError {
	env := r.Context().Value("env").(Settings)
	var user User
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&user)
	if err != nil {
		return &AppError{http.StatusBadRequest, errors.Trace(err)}
	}

	auth, err := Authenticate(env.GetLDAP(), user.Username, user.Password)
	if err != nil {
		return &AppError{http.StatusInternalServerError, errors.Trace(err)}
	}

	if !auth {
		return &AppError{http.StatusForbidden, errors.Errorf("Invalid login")}
	} else {
		ldapuser, err := GetUser(env.GetLDAP(), user.Username)
		if err != nil {
			return &AppError{http.StatusInternalServerError, errors.Trace(err)}
		}
		err = env.GetEvents().OnLogin(ldapuser)
		if err != nil {
			return &AppError{http.StatusInternalServerError, errors.Trace(err)}
		}
		t := jwt.New(jwt.SigningMethodRS512)
		t.Header["x5c"] = []string{string(env.GetJWTPublicKey())}
		t.Claims.(jwt.MapClaims)["username"] = user.Username
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Minute * 30).Unix()
		token, err := t.SignedString(env.GetJWTSigningKey())
		if err != nil {
			return &AppError{http.StatusInternalServerError, errors.Trace(err)}
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, fmt.Sprintf("{\"token\": \"%s\"}", token))
		return nil
	}
}

// Does nothing for now
func LogoutHandler(w http.ResponseWriter, r *http.Request) *AppError {
	// maybe have an in-memory LRU cache that takes in explicit logouts and
	// blacklists them to check against in the Auth middleware above
	return nil
}

// Takes an existing, valid token and issues a newer, fresher expiration
// for it.
func RefreshHandler(w http.ResponseWriter, r *http.Request) *AppError {
	env := r.Context().Value("env").(Settings)
	// Consider modifying this to allow an expired token within a grace
	// period to obtain a refreshed token.

	t := r.Context().Value(env.GetJWT().Options.UserProperty).(*jwt.Token)
	t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Minute * 15).Unix()
	token, err := t.SignedString(env.GetJWTSigningKey())
	if err != nil {
		return &AppError{http.StatusInternalServerError, errors.Trace(err)}
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, fmt.Sprintf("{\"token\": \"%s\"}", token))
	return nil
}
