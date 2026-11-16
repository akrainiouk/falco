package config

import (
	"strings"
	"testing"
)

func TestParseHeaderTemplate(t *testing.T) {
	vars := map[string]string{
		"backend.name": "bknd1",
		"backend.host": "origin.example.com",
	}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty string", input: "", want: ""},
		{name: "plain literal", input: "hello world", want: "hello world"},
		{name: "backend name", input: "${backend.name}", want: "bknd1"},
		{name: "backend host", input: "${backend.host}", want: "origin.example.com"},
		{
			name:  "placeholder with surrounding whitespace",
			input: "${ backend.name }",
			want:  "bknd1",
		},
		{
			name:  "mixed literal and placeholders",
			input: "prefix-${backend.name}-${backend.host}-suffix",
			want:  "prefix-bknd1-origin.example.com-suffix",
		},
		{name: "double dollar escape", input: "$$", want: "$"},
		{
			name:  "escaped placeholder renders literal",
			input: "$${backend.name}",
			want:  "${backend.name}",
		},
		{name: "lone dollar not followed by brace", input: "price is $10", want: "price is $10"},
		{
			name:  "trailing dollar sign",
			input: "cost$",
			want:  "cost$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl, err := ParseHeaderTemplate(tt.input)
			if err != nil {
				t.Fatalf("ParseHeaderTemplate(%q) returned error: %s", tt.input, err)
			}
			if got := tmpl.Render(vars); got != tt.want {
				t.Errorf("Render mismatch: input=%q got=%q want=%q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseHeaderTemplateErrors(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantSubstr  string
		wantVarName string
	}{
		{name: "unterminated placeholder", input: "${backend.name", wantSubstr: "unterminated"},
		{name: "empty placeholder", input: "${}", wantSubstr: "empty placeholder"},
		{
			name:       "whitespace only placeholder",
			input:      "${  }",
			wantSubstr: "empty placeholder",
		},
		{
			name:        "unknown variable",
			input:       "${req.http.host}",
			wantSubstr:  "unsupported variable",
			wantVarName: "req.http.host",
		},
		{
			name:        "typo in supported variable",
			input:       "${backend.hostname}",
			wantSubstr:  "unsupported variable",
			wantVarName: "backend.hostname",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseHeaderTemplate(tt.input)
			if err == nil {
				t.Fatalf("ParseHeaderTemplate(%q) expected error, got nil", tt.input)
			}
			msg := err.Error()
			if !strings.Contains(msg, tt.wantSubstr) {
				t.Errorf("error message %q does not contain %q", msg, tt.wantSubstr)
			}
			if tt.wantVarName != "" && !strings.Contains(msg, tt.wantVarName) {
				t.Errorf("error message %q does not mention variable %q", msg, tt.wantVarName)
			}
		})
	}
}

func TestHeaderTemplateRenderMissingVar(t *testing.T) {
	// A supported variable with no value in the vars map should render empty
	// rather than panic; the config layer guarantees only supported variables
	// reach this code path.
	tmpl, err := ParseHeaderTemplate("[${backend.name}]")
	if err != nil {
		t.Fatalf("unexpected parse error: %s", err)
	}
	if got := tmpl.Render(map[string]string{}); got != "[]" {
		t.Errorf("unexpected render: got %q, want %q", got, "[]")
	}
}
