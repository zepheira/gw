package gw

import (
	"testing"
)

var cases = []struct {
	origin  string
	method  string
	allowed bool
}{
	{"http://example.com", "GET", true},
	{"http://find.example.com/search.html", "POST", true},
	{"http://example.net", "GET", false},
	{"http://example.com.not", "POST", false},
}

func TestAllowedOriginMethod(t *testing.T) {
	opts := &CORSOptions{
		Origins: []string{"example.com"},
	}
	for _, test := range cases {
		allowed := AllowedOriginMethod(opts, test.origin, test.method)
		if test.allowed != allowed {
			t.Error("%s %s was %v instead of %v", test.origin, test.method, allowed, test.allowed)
		}
	}
}
