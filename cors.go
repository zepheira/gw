package gw

import (
	"net/http"
	"net/url"
	"strings"
)

type CORSOptions struct {
	Origins []string `json:"origins"`
}

func AllowedOriginMethod(opts *CORSOptions, origin, method string) bool {
	o, err := url.Parse(origin)
	if err != nil {
		return false
	}
	for _, opt := range opts.Origins {
		if o.Host == opt || strings.HasSuffix(o.Host, "."+opt) {
			if method == "GET" || method == "POST" {
				return true
			}
		}
	}
	return false
}

func CORS(fn AppHandler) AppHandler {
	return func(w http.ResponseWriter, r *http.Request) *AppError {
		env := r.Context().Value("env").(Settings)
		co := env.GetCORSOptions()
		origin := r.Header.Get("Origin")
		method := r.Header.Get("Access-Control-Request-Method")
		if r.Method == "OPTIONS" {
			if origin != "" {
				if AllowedOriginMethod(co, origin, method) {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
					w.Header().Set("Access-Control-Allow-Headers", "origin, content-type, content-length, accept, accept-encoding, accept-language, referer, user-agent")
					w.Header().Set("Allow", "GET, POST")
					return nil
				}
				// Not in allowed origins, ok but no additional headers
				return nil
			}
			// Empty preflight, ok but no additional headers
			return nil
		} else {
			if AllowedOriginMethod(co, origin, r.Method) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				return fn(w, r)
			} else {
				return fn(w, r)
			}
		}
	}
}
