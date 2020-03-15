package mux

import "net/http"

type exactMuxEntry struct {
	pattern string
	handler http.Handler
}
