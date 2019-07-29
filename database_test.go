package gw

import (
	"net/http"
	"testing"
)

func TestQuerySetHelper(t *testing.T) {
	tr, _ := http.NewRequest("GET", "/?start=2&count=10&field=some&order=ascend", nil)
	tvals := tr.URL.Query()
	ts, err := QuerySetHelper(tvals, "", "")
	if err != nil {
		t.Error("Error in generating suffix", err)
	}

	if ts.Compiled != " ORDER BY some ASC LIMIT 10 OFFSET 2" {
		t.Error("Unexpected query suffix", ts)
	}

	tr, _ = http.NewRequest("GET", "/?start=3&count=15", nil)
	tvals = tr.URL.Query()
	ts, err = QuerySetHelper(tvals, "foo", DESC)
	if err != nil {
		t.Error("Error in generating suffix", err)
	}

	if ts.Compiled != " ORDER BY foo DESC LIMIT 15 OFFSET 3" {
		t.Error("Unexpected query suffix", ts)
	}
}
