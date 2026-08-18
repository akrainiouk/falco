package config

import (
	"strings"
	"testing"
)

func TestOverrideBackendParseHeaders(t *testing.T) {
	ob := &OverrideBackend{
		Headers: map[string]string{
			"X-Backend-Name":  "${backend.name}",
			"X-Original-Host": "prefix-${backend.host}",
			"X-Token":         "static-value",
		},
	}
	if err := ob.parseHeaders(); err != nil {
		t.Fatalf("parseHeaders returned unexpected error: %s", err)
	}
	if len(ob.ParsedHeaders) != 3 {
		t.Fatalf("expected 3 parsed headers, got %d", len(ob.ParsedHeaders))
	}
	seen := map[string]string{}
	vars := map[string]string{
		"backend.name": "bknd1",
		"backend.host": "origin.example.com",
	}
	for _, h := range ob.ParsedHeaders {
		seen[h.Name] = h.Value.Render(vars)
	}
	want := map[string]string{
		"X-Backend-Name":  "bknd1",
		"X-Original-Host": "prefix-origin.example.com",
		"X-Token":         "static-value",
	}
	for k, v := range want {
		if got := seen[k]; got != v {
			t.Errorf("header %q: got %q, want %q", k, got, v)
		}
	}
}

func TestOverrideBackendParseHeadersEmpty(t *testing.T) {
	ob := &OverrideBackend{}
	if err := ob.parseHeaders(); err != nil {
		t.Fatalf("parseHeaders returned unexpected error: %s", err)
	}
	if ob.ParsedHeaders != nil {
		t.Errorf("expected nil ParsedHeaders for empty Headers, got %v", ob.ParsedHeaders)
	}
}

func TestOverrideBackendParseHeadersErrors(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		wantSubstr string
	}{
		{
			name:       "empty header name",
			headers:    map[string]string{"": "value"},
			wantSubstr: "must not be empty",
		},
		{
			name:       "header name with space",
			headers:    map[string]string{"X Bad Name": "value"},
			wantSubstr: "invalid header name",
		},
		{
			name:       "header name with control character",
			headers:    map[string]string{"X-Bad\nName": "value"},
			wantSubstr: "invalid header name",
		},
		{
			name:       "header name too long",
			headers:    map[string]string{strings.Repeat("a", 127): "value"},
			wantSubstr: "invalid header name",
		},
		{
			name:       "malformed template propagates",
			headers:    map[string]string{"X-Foo": "${backend.name"},
			wantSubstr: `header "X-Foo"`,
		},
		{
			name:       "unsupported variable propagates",
			headers:    map[string]string{"X-Foo": "${req.http.host}"},
			wantSubstr: "unsupported variable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ob := &OverrideBackend{Headers: tt.headers}
			err := ob.parseHeaders()
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSubstr)
			}
		})
	}
}
