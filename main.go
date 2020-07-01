package main

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/zMrKrabz/golang-jwt-example/controller"
)

func main() {
	r := router()

	http.ListenAndServe(":8080", r)
}

func router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello"))
	})
	r.Post("/login", controller.Login)
	r.Get("/refresh", controller.RefreshAccessToken)
	r.Post("/secret", controller.GetSecret)

	return r
}
