package gw

import (
	"path/filepath"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
	"html/template"
	"github.com/juju/errors"
)

func ListenForReload(c Settings, dir string) {
	for {
		signal_channel := make(chan os.Signal, 1)
		signal.Notify(signal_channel, syscall.SIGUSR1)
		<- signal_channel
		tmpls, err := LoadTemplates(dir)
		if err != nil {
			log.Print(err)
		}
		c.SetTemplates(tmpls)
	}
}

func LoadTemplates(directory string) (map[string]*template.Template, error) {
	tmpls := make(map[string]*template.Template)
	fullDir, err := filepath.Abs(directory)
	if err != nil {
		return nil, errors.Trace(err)
	}
	fs, err := ioutil.ReadDir(fullDir)
	if err != nil {
		return nil, errors.Trace(err)
	}
	for _, f := range fs {
		if !f.IsDir() && f.Name() != "base.html" {
			if filepath.Ext(f.Name()) == ".html" {
				tmpls[filepath.Base(f.Name())] = template.Must(template.New("").Delims("<<", ">>").ParseFiles(filepath.Join(fullDir, "base.html"), filepath.Join(fullDir, f.Name())))
			}
		}

		// assuming only one level of subdirectories in views
		if f.IsDir() {
			sfs, serr := ioutil.ReadDir(filepath.Join(fullDir, f.Name()))
			if serr != nil {
				return nil, errors.Trace(serr)
			}
			for _, sf := range sfs {
				if filepath.Ext(sf.Name()) == ".html" {
					tmpls[f.Name() + "/" + filepath.Base(sf.Name())] = template.Must(template.New("").Delims("<<", ">>").ParseFiles(filepath.Join(fullDir, "base.html"), filepath.Join(fullDir, f.Name(), sf.Name())))
				}
			}
		}
	}
	return tmpls, nil
}
