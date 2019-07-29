package gw

import (
	"github.com/gorilla/mux"
	"github.com/juju/errors"
	"net/http"
	"path/filepath"
)

func TemplatesRegister(router *mux.Router, c Settings) {
	for tmpl, _ := range c.GetTemplates() {
		if tmpl == "index.html" {
			router.
				Handle(
					"/",
					Middleware(TemplateMiddleware(tmpl), c)).
				Methods("GET")
		} else if filepath.Base(tmpl) == "index.html" {
			router.
				Handle(
					"/"+filepath.Dir(tmpl)+"/",
					Middleware(TemplateMiddleware(tmpl), c)).
				Methods("GET")
		} else {
			router.
				Handle(
					"/"+tmpl,
					Middleware(TemplateMiddleware(tmpl), c)).
				Methods("GET")
		}
	}
}

func TemplateMiddleware(tmpl string) AppHandler {
	return func(w http.ResponseWriter, r *http.Request) *AppError {
		return TemplateHandler(w, r, tmpl)
	}
}

func TemplateHandler(w http.ResponseWriter, r *http.Request, template string) *AppError {
	env := r.Context().Value("env").(Settings)
	tmpl, ok := env.GetTemplates()[template]
	if !ok {
		return &AppError{http.StatusInternalServerError, errors.Errorf("The template %s does not exist.", template)}
	}

	buf := env.GetPool().Get()
	err := tmpl.ExecuteTemplate(buf, "base", nil)
	if err != nil {
		env.GetPool().Put(buf)
		return &AppError{http.StatusInternalServerError, errors.Trace(err)}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
	env.GetPool().Put(buf)
	return nil
}
