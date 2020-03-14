package authenticated

import (
	"context"
	"net/http"
)

func Authenticated(vasya func(ctx context.Context) bool) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			if !vasya(request.Context()) {
				http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			next(writer, request)
		}
	}
}

