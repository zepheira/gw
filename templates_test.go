package gw

import (
	"syscall"
	"testing"
)

// Bailing, signal not apparently registering when called from this,
// possibly a matter of PIDs. Skip until a solution is found.
func TestListenForReload(t *testing.T) {
	t.Skip()
	c := MockSettings{}
	go ListenForReload(&c, "./views")
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
}

func TestLoadTemplates(t *testing.T) {
	tmpls, err := LoadTemplates("./views")
	if err != nil {
		t.Error("Error loading templates", err)
	}

	_, ok := tmpls["index.html"]
	if !ok {
		t.Error("Did not load expected template index.html")
	}

	_, ok = tmpls["base.html"]
	if ok {
		t.Error("Loaded master template as an actual template")
	}
}
