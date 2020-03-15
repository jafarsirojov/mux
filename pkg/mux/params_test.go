package mux

import (
	"reflect"
	"testing"
)

func TestParsePathParams(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want []string
	}{
		{name: "no path param", url: "/posts/", want: []string{}},
		{name: "single path param", url: "/posts/{id}", want: []string{"id"}},
		{name: "multiple path params", url: "/posts/{postId}/comments/{commentId}", want: []string{"postId", "commentId"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := parsePathParams(tt.url)
			if got := params.placeholders(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePathParams() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePathPart(t *testing.T) {
	tests := []struct {
		name string
		part string
		want PathPart
	}{
		{name: "empty", part: "", want: PathPart{name: "", placeholder: false}},
		{name: "regular", part: "posts", want: PathPart{name: "posts", placeholder: false}},
		{name: "placeholder", part: "{id}", want: PathPart{name: "id", placeholder: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParsePathPart(tt.part); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePathPart() = %v, want %v", got, tt.want)
			}
		})
	}
}
