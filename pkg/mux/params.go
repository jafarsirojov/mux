package mux

import (
	"fmt"
	"net/http"
	"strings"
)

type paramsMuxEntry struct {
	pattern string
	params  []PathPart
	weight  int
	handler http.Handler
}

func (p *paramsMuxEntry) placeholders() []string {
	result := make([]string, 0)

	for _, param := range p.params {
		if !param.placeholder {
			continue
		}
		result = append(result, param.name)
	}
	return result
}

func (p *paramsMuxEntry) Match(path string) (map[string]string, bool) {
	parts := strings.Split(path, "/")
	if len(parts) != len(p.params) {
		return nil, false
	}

	params := make(map[string]string)

	for index, param := range p.params {
		if !param.placeholder {
			if param.name != parts[index] {
				return nil, false
			}
			continue
		}

		if parts[index] == "" {
			return nil, false
		}

		params[param.name] = parts[index]
	}

	return params, true
}

type PathPart struct {
	name        string
	placeholder bool
}

func parsePathParams(pattern string) paramsMuxEntry {
	parts := strings.Split(pattern, "/")
	params := paramsMuxEntry{
		pattern: pattern,
		params:  make([]PathPart, 0, len(parts)),
		weight:  calculateWeight(pattern),
	}
	for _, part := range parts {
		params.params = append(params.params, ParsePathPart(part))
	}
	return params
}

func ParsePathPart(part string) PathPart {
	if part == "" {
		pathPart := PathPart{
			name:        part,
			placeholder: false,
		}
		return pathPart
	}

	if part[0] == '{' {
		if part[len(part)-1] != '}' {
			panic(fmt.Errorf("invalid path part: %s", part))
		}

		pathPart := PathPart{
			name:        part[1 : len(part)-1],
			placeholder: true,
		}

		return pathPart
	}

	pathPart := PathPart{
		name:        part,
		placeholder: false,
	}

	return pathPart
}

func calculateWeight(pattern string) int {
	if pattern == "/" {
		return 0
	}

	count := (strings.Count(pattern, "/") - 1) * 2
	if !strings.HasSuffix(pattern, "/") {
		return count + 1
	}
	return count
}
