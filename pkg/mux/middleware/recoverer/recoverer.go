package recoverer

import (
	"log"
	"net/http"
	"runtime/debug"
)

func Recoverer() func(
	next http.HandlerFunc,
) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			// may panic
			// handle panic
			defer func() {
				if err := recover(); err != nil {
					log.Printf("%s", debug.Stack())
					http.Error(
						writer,
						http.StatusText(http.StatusInternalServerError),
						http.StatusInternalServerError,
					)
				}
			}()
			next(writer, request)
		}
	}
}
