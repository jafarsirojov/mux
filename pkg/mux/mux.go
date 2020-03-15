package mux

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type contextKey string // int?
var pathParamsKey = contextKey("params")

// TODO: optimization map[string]map[int][]paramsMuxEntry, where int - weight
type ExactMux struct {
	mutex           sync.RWMutex
	exactRoutes     map[string]map[string]exactMuxEntry
	paramRoutes     map[string][]paramsMuxEntry
	notFoundHandler http.Handler
}

type Middleware func(handler http.HandlerFunc) http.HandlerFunc

func NewExactMux() *ExactMux {
	return &ExactMux{}
}

func (m *ExactMux) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request, handler, err := m.handler(request.Method, request.URL.Path, request); err == nil {
		handler.ServeHTTP(writer, request)
	}

	if m.notFoundHandler != nil {
		m.notFoundHandler.ServeHTTP(writer, request)
	}

	writer.WriteHeader(404)
}

func (m *ExactMux) GET(
	pattern string,
	handlerFunc http.HandlerFunc,
	middlewares ...Middleware,
) {
	m.HandleFuncWithMiddlewares(
		http.MethodGet,
		pattern,
		handlerFunc,
		middlewares...,
	)
}

func (m *ExactMux) POST(
	pattern string,
	handlerFunc http.HandlerFunc,
	middlewares ...Middleware,
) {
	m.HandleFuncWithMiddlewares(
		http.MethodPost,
		pattern,
		handlerFunc,
		middlewares...,
	)
}

func (m *ExactMux) DELETE(
	pattern string,
	handlerFunc http.HandlerFunc,
	middlewares ...Middleware,
) {
	m.HandleFuncWithMiddlewares(
		http.MethodDelete,
		pattern,
		handlerFunc,
		middlewares...,
	)
}

func (m *ExactMux) HandleFuncWithMiddlewares(
	method string,
	pattern string,
	handlerFunc http.HandlerFunc,
	middlewares ...Middleware,
) {
	for _, middleware := range middlewares {
		handlerFunc = middleware(handlerFunc)
	}
	m.HandleFunc(method, pattern, handlerFunc)
}

func (m *ExactMux) HandleFunc(method string, pattern string, handlerFunc http.HandlerFunc) {
	// pattern: "/..."
	if !strings.HasPrefix(pattern, "/") {
		panic(fmt.Errorf("pattern must start with /: %s", pattern))
	}

	if handlerFunc == nil { // ?
		panic(errors.New("handler can't be empty"))
	}

	if isExact(pattern) {
		m.AddExact(method, pattern, handlerFunc)
		return
	}

	m.AddParams(method, pattern, handlerFunc)
}

func (m *ExactMux) AddExact(method string, pattern string, handlerFunc http.HandlerFunc) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	entry := exactMuxEntry{
		pattern: pattern,
		handler: http.HandlerFunc(handlerFunc),
	}

	// запретить добавлять дубликаты
	if _, exists := m.exactRoutes[method][pattern]; exists {
		panic(fmt.Errorf("ambigious mapping: %s", pattern))
	}

	if m.exactRoutes == nil {
		m.exactRoutes = make(map[string]map[string]exactMuxEntry)
	}

	if m.exactRoutes[method] == nil {
		m.exactRoutes[method] = make(map[string]exactMuxEntry)
	}

	m.exactRoutes[method][pattern] = entry
}

func (m *ExactMux) AddParams(method string, pattern string, handlerFunc http.HandlerFunc) {
	entry := parsePathParams(pattern)
	entry.handler = handlerFunc

	if m.paramRoutes == nil {
		m.paramRoutes = make(map[string][]paramsMuxEntry)
	}

	if m.paramRoutes[method] == nil {
		m.paramRoutes[method] = make([]paramsMuxEntry, 0)
	}

	m.paramRoutes[method] = append(m.paramRoutes[method], entry)
}

func (m *ExactMux) handler(method string, path string, original *http.Request) (result *http.Request, handler http.Handler, err error) {
	exactEntries, exactExists := m.exactRoutes[method]
	if exactExists {
		if entry, ok := exactEntries[path]; ok {
			return original, entry.handler, nil
		}
	}

	paramEntries, paramExists := m.paramRoutes[method]
	if !paramExists {
		return nil, nil, fmt.Errorf("no handlers for %s, %s", method, path)
	}

	weight := calculateWeight(path)
	for _, paramEntry := range paramEntries {
		if weight != paramEntry.weight {
			continue
		}

		if params, ok := paramEntry.Match(path); ok {
			ctx := context.WithValue(original.Context(), pathParamsKey, params)
			result = original.WithContext(ctx)
			return result, paramEntry.handler, nil
		}
	}

	return nil, nil, fmt.Errorf("can't find handler for: %s, %s", method, path)
}

func FromContext(ctx context.Context, key string) (value string, ok bool) {
	params, ok := ctx.Value(pathParamsKey).(map[string]string)
	param, exists := params[key]
	return param, exists
}

func isExact(pattern string) bool {
	return !strings.Contains(pattern, "{")
}



//package mux
//
//import (
//	"errors"
//	"fmt"
//	"net/http"
//	"sort"
//	"strings"
//	"sync"
//)
//
//// GET - список, привязывать Handler
//// Уметь извлекать параметры запросов
//// https://vk.com/id{number}
//
//// Chi
//// Gorilla Mux
//// map["GET"] - map["/"] - handler GET
//// map["POST"] - map["/"] - handler POST
//// specific: "/", "/catalog/", "/catalog/4234234", "/asdfasdfasfasdfasfasdfasdfasdf"
//type ExactMux struct {
//	mutex           sync.RWMutex
//	routes          map[string]map[string]exactMuxEntry
//	routesSorted    map[string][]exactMuxEntry
//	notFoundHandler http.Handler
//}
//
//type Middleware func(handler http.HandlerFunc) http.HandlerFunc
//
//func NewExactMux() *ExactMux {
//	return &ExactMux{}
//}
//
//func (m *ExactMux) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
//	// TODO:
//	//ctx, cancel := context.WithTimeout(request.Context(), time.Second * 5)
//	//// pass created context to next functions
//	//request = request.WithContext(ctx) // copy original with new context
//	//// pass to others - copied request
//	//defer func() {
//	//	log.Print(ctx.Err())
//	//	cancel()
//	//	if ctx.Err() == context.DeadlineExceeded {
//	//		writer.WriteHeader(http.StatusGatewayTimeout)
//	//	}
//	//}()
//
//	if handler, err := m.handler(request.Method, request.URL.Path); err == nil {
//		handler.ServeHTTP(writer, request)
//	}
//
//	if m.notFoundHandler != nil {
//		m.notFoundHandler.ServeHTTP(writer, request)
//	}
//}
//
//func (m *ExactMux) GET(
//	pattern string,
//	handlerFunc http.HandlerFunc,
//	middlewares ...Middleware,
//) {
//	m.HandleFuncWithMiddlewares(
//		http.MethodGet,
//		pattern,
//		handlerFunc,
//		middlewares...,
//	)
//}
//
//func (m *ExactMux) POST(
//	pattern string,
//	handlerFunc http.HandlerFunc,
//	middlewares ...Middleware,
//) {
//	m.HandleFuncWithMiddlewares(
//		http.MethodPost,
//		pattern,
//		handlerFunc,
//		middlewares...,
//	)
//}
//
//
//func (m *ExactMux) DELETE(
//	pattern string,
//	handlerFunc http.HandlerFunc,
//	middlewares ...Middleware,
//) {
//	m.HandleFuncWithMiddlewares(
//		http.MethodDelete,
//		pattern,
//		handlerFunc,
//		middlewares...,
//	)
//}
//
//func (m *ExactMux) HandleFuncWithMiddlewares(
//	method string,
//	pattern string,
//	handlerFunc http.HandlerFunc,
//	middlewares ...Middleware,
//)  {
//	for _, middleware := range middlewares {
//		handlerFunc = middleware(handlerFunc)
//	}
//	m.HandleFunc(method, pattern, handlerFunc)
//}
//
//func (m *ExactMux) HandleFunc(method string, pattern string, handlerFunc func(responseWriter http.ResponseWriter, request *http.Request)) {
//	// pattern: "/..."
//	if !strings.HasPrefix(pattern, "/") {
//		panic(fmt.Errorf("pattern must start with /: %s", pattern))
//	}
//
//	if handlerFunc == nil { // ?
//		panic(errors.New("handler can't be empty"))
//	}
//
//	// TODO: check method
//	m.mutex.Lock()
//	defer m.mutex.Unlock()
//	entry := exactMuxEntry{
//		pattern: pattern,
//		handler: http.HandlerFunc(handlerFunc),
//		weight:  calculateWeight(pattern),
//	}
//
//	// запретить добавлять дубликаты
//	if _, exists := m.routes[method][pattern]; exists {
//		panic(fmt.Errorf("ambigious mapping: %s", pattern))
//	}
//
//	if m.routes == nil {
//		m.routes = make(map[string]map[string]exactMuxEntry)
//	}
//
//	if m.routes[method] == nil {
//		m.routes[method] = make(map[string]exactMuxEntry)
//	}
//
//	m.routes[method][pattern] = entry
//	m.appendSorted(method, entry)
//}
//
//func (m *ExactMux) appendSorted(method string, entry exactMuxEntry) {
//	if m.routesSorted == nil {
//		m.routesSorted = make(map[string][]exactMuxEntry)
//	}
//
//	if m.routesSorted[method] == nil {
//		m.routesSorted[method] = make([]exactMuxEntry, 0)
//	}
//	// TODO: rewrite to append
//	routes := append(m.routesSorted[method], entry)
//	sort.Slice(routes, func(i, j int) bool {
//		return routes[i].weight > routes[j].weight
//	})
//	m.routesSorted[method] = routes
//}
//
//func (m *ExactMux) handler(method string, path string) (handler http.Handler, err error) {
//	entries, exists := m.routes[method]
//	if !exists {
//		return nil, fmt.Errorf("can't find handler for: %s, %s", method, path)
//	}
//
//	if entry, ok := entries[path]; ok {
//		return entry.handler, nil
//	}
//
//	sortedEntries, sortedExists := m.routesSorted[method]
//	if !sortedExists {
//		return nil, fmt.Errorf("can't find handler for: %s, %s", method, path)
//	}
//	for _, entry := range sortedEntries {
//		if strings.HasPrefix(path, entry.pattern) {
//			return entry.handler, nil
//		}
//	}
//
//	return nil, fmt.Errorf("can't find handler for: %s, %s", method, path)
//}
//
//type exactMuxEntry struct {
//	pattern string
//	handler http.Handler
//	weight  int
//}
//
//func calculateWeight(pattern string) int {
//	if pattern == "/" {
//		return 0
//	}
//
//	count := (strings.Count(pattern, "/") - 1) * 2
//	if !strings.HasSuffix(pattern, "/") {
//		return count + 1
//	}
//	return count
//}
