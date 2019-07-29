package gw

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/getsentry/raven-go"
	"github.com/gorilla/mux"
	"github.com/juju/errors"
	"mime"
	"net/http"
	"strings"
)

// Code is HTTP status code, Error the Go error describing the problem,
// possibly for re-display to the user.
type AppError struct {
	Code  int
	Error error
}

type ErrorInfo struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
}

type AppHandler func(http.ResponseWriter, *http.Request) *AppError

func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := fn(w, r); err != nil {
		switch err.Code {
		case http.StatusNotFound:
			http.NotFound(w, r)
		case http.StatusBadRequest:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			enc := json.NewEncoder(w)
			serr := enc.Encode(&ErrorInfo{
				Code:  http.StatusBadRequest,
				Error: err.Error.Error(),
			})
			if serr != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		case http.StatusMethodNotAllowed, http.StatusGone, http.StatusUnauthorized, http.StatusForbidden, http.StatusUnsupportedMediaType:
			http.Error(w, http.StatusText(err.Code), err.Code)
		default:
			if raven.URL() != "" {
				raven.SetHttpContext(raven.NewHttp(r))
				raven.CaptureMessage(errors.ErrorStack(err.Error), nil)
				raven.ClearContext()
			}
			http.Error(w, fmt.Sprintf("%s - %s", http.StatusText(err.Code), err.Error), err.Code)
		}
	}
}

// Always conclude by wrapping handlers in Middleware.  If there are
// exceptions to this rule, it should be because no level requires context.
// All other wrappers depend on it; for instance, AuthRequired needs the
// context to determine logged-in status.
func Middleware(fn AppHandler, c interface{}) AppHandler {
	return func(w http.ResponseWriter, r *http.Request) *AppError {
		r = r.WithContext(context.WithValue(r.Context(), "env", c))
		r = r.WithContext(context.WithValue(r.Context(), "vars", mux.Vars(r)))
		return fn(w, r)
	}
}

func SendJSON(data interface{}, w http.ResponseWriter, r *http.Request) *AppError {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	err := enc.Encode(data)
	if err != nil {
		return &AppError{
			Code:  http.StatusInternalServerError,
			Error: errors.Trace(err),
		}
	}
	return nil
}

func ReceiveJSON(data interface{}, r *http.Request) *AppError {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" {
		return &AppError{
			Code:  http.StatusUnsupportedMediaType,
			Error: errors.Errorf("Expected application/json but got %s", ct),
		}
	}

	decoder := json.NewDecoder(r.Body)
	// @@@ may be an issue in here with an empty body resulting in panic
	err := decoder.Decode(data)
	if err != nil {
		return &AppError{
			Code:  http.StatusInternalServerError,
			Error: errors.Trace(err),
		}
	}
	return nil
}

func ParseJSON(data interface{}, query string) *AppError {
	decoder := json.NewDecoder(strings.NewReader(query))
	err := decoder.Decode(data)
	if err != nil {
		return &AppError{
			Code:  http.StatusInternalServerError,
			Error: errors.Trace(err),
		}
	}
	return nil
}
