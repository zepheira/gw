package gw

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"encoding/json"
	"testing"
	"github.com/gorilla/mux"
	"github.com/juju/errors"
)

func okHandler(w http.ResponseWriter, r *http.Request) (*AppError) {
	return nil
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) (*AppError) {
	return &AppError{http.StatusNotFound, nil}
}

func notAllowedHandler(w http.ResponseWriter, r *http.Request) (*AppError) {
	return &AppError{http.StatusMethodNotAllowed, nil}
}

func badRequestHandler(w http.ResponseWriter, r *http.Request) (*AppError) {
	return &AppError{http.StatusBadRequest, errors.Errorf("Missing field")}
}

func forbiddenHandler(w http.ResponseWriter, r *http.Request) (*AppError) {
	return &AppError{http.StatusForbidden, nil}
}

func serverErrorHandler(w http.ResponseWriter, r *http.Request) (*AppError) {
	return &AppError{http.StatusInternalServerError, nil}
}

func testMiddleware(fn AppHandler) AppHandler {
	return func(w http.ResponseWriter, r *http.Request) *AppError {
		return fn(w, r)
	}
}

func setupRawHandlers(m *mux.Router) {
	m.Handle("/not/aproblem", testMiddleware(okHandler))
	m.Handle("/not/found", testMiddleware(notFoundHandler))
	m.Handle("/not/allowed", testMiddleware(notAllowedHandler))
	m.Handle("/not/understood", testMiddleware(badRequestHandler))
	m.Handle("/not/permitted", testMiddleware(forbiddenHandler))
	m.Handle("/not/working", testMiddleware(serverErrorHandler))
}

func setupHandlers(m *mux.Router) {
	c := MockSettings{}
	m.Handle("/not/aproblem", Middleware(okHandler, c))
	m.Handle("/not/found", Middleware(notFoundHandler, c))
	m.Handle("/not/allowed", Middleware(notAllowedHandler, c))
	m.Handle("/not/understood", Middleware(badRequestHandler, c))
	m.Handle("/not/permitted", Middleware(forbiddenHandler, c))
	m.Handle("/not/working", Middleware(serverErrorHandler, c))
}

func sendJsonHandler(w http.ResponseWriter, r *http.Request) (*AppError) {
	return SendJSON(map[string]interface{}{"foo":"bar"}, w, r)
}

type ReceiveTest struct {
	Foo string `json:"foo"`
}

func receiveJsonHandler(w http.ResponseWriter, r *http.Request) (*AppError) {
	var rt ReceiveTest
	return ReceiveJSON(&rt, r)
}

func TestServeHTTP(t *testing.T) {
	m := mux.NewRouter()
	setupRawHandlers(m)

	resp := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/not/found", nil)
	m.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Errorf("Status not %v: %v", http.StatusNotFound, resp.Code)
	}

	resp = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/not/allowed", nil)
	m.ServeHTTP(resp, req)
	if resp.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status not %v: %v", http.StatusMethodNotAllowed, resp.Code)
	}

	resp = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/not/permitted", nil)
	m.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Errorf("Status not %v: %v", http.StatusForbidden, resp.Code)
	}

	resp = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/not/understood", nil)
	m.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Status not %v: %v", http.StatusBadRequest, resp.Code)
	}

	var answer ErrorInfo
	decoder := json.NewDecoder(resp.Body)
	err := decoder.Decode(&answer)
	if err != nil {
		t.Error("Error decoding error JSON")
	}
	if answer.Error != "Missing field" {
		t.Error("Error in sending error JSON")
	}

	resp = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/not/working", nil)
	m.ServeHTTP(resp, req)
	if resp.Code != http.StatusInternalServerError {
		t.Errorf("Status not %v: %v", http.StatusInternalServerError, resp.Code)
	}

	resp = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/not/aproblem", nil)
	m.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Status not %v: %v", http.StatusOK, resp.Code)
	}
}

// Bail, kind of hard to see inside
func TestMiddleware(t *testing.T) {
	t.Skip()
}

func TestServeJSON(t *testing.T) {
	m := mux.NewRouter()
	m.Handle("/stuff", testMiddleware(sendJsonHandler))
	resp := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/stuff", nil)
	m.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Status not %v: %v", http.StatusOK, resp.Code)
	}

	var answer map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	err := decoder.Decode(&answer)
	if err != nil {
		t.Error("Error decoding JSON")
	}
	if answer["foo"].(string) != "bar" {
		t.Error("Error in sending JSON")
	}
}

func TestReceiveJSON(t *testing.T) {
	m := mux.NewRouter()
	m.Handle("/stuff", testMiddleware(receiveJsonHandler))
	resp := httptest.NewRecorder()
	reqJSON := []byte(`{"foo":"bar"}`)
	req, _ := http.NewRequest("POST", "/stuff", bytes.NewBuffer(reqJSON))
	req.Header.Add("Content-Type", "application/json")
	m.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Status not %v: %v", http.StatusOK, resp.Code)
	}
}
