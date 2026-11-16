package interpreter

import (
	ghttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/config"
	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/http"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

// backendProperty builds a *ast.BackendProperty with the given key and value
// expression, bypassing the VCL parser so that we can construct property
// values of any type (including combinations the parser might later reject).
func backendProperty(key string, val ast.Expression) *ast.BackendProperty {
	return &ast.BackendProperty{
		Key:   &ast.Ident{Value: key},
		Value: val,
	}
}

// newBackend constructs a *value.Backend directly from the provided
// properties, without going through the parser.
func newBackend(name string, props ...*ast.BackendProperty) *value.Backend {
	return &value.Backend{
		Value: &ast.BackendDeclaration{
			Name:       &ast.Ident{Value: name},
			Properties: props,
		},
	}
}

// TestCreateBackendRequestWithInvalidPropertyType verifies that createBackendRequest
// returns an error (rather than panicking with a nil-pointer dereference) when
// a backend declaration assigns a value of an unexpected type to one of the
// properties consumed by createBackendRequest.
//
// Backends are constructed directly instead of via the parser so that these
// cases remain reproducible even if the parser starts rejecting mismatched
// property types up-front.
func TestCreateBackendRequestWithInvalidPropertyType(t *testing.T) {
	tests := []struct {
		name     string
		backend  *value.Backend
		property string
	}{
		{
			name: "host must be string",
			backend: newBackend("invalid_host_type",
				backendProperty("host", &ast.Integer{Value: 1234}),
			),
			property: "host",
		},
		{
			name: "port must be string",
			backend: newBackend("invalid_port_type",
				backendProperty("host", &ast.String{Value: "example.com"}),
				backendProperty("port", &ast.Integer{Value: 443}),
			),
			property: "port",
		},
		{
			name: "ssl must be boolean",
			backend: newBackend("invalid_ssl_type",
				backendProperty("host", &ast.String{Value: "example.com"}),
				backendProperty("ssl", &ast.String{Value: "true"}),
			),
			property: "ssl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := New()
			ip.ctx = context.New()

			_, err := ip.createBackendRequest(ip.ctx, tt.backend)
			if err == nil {
				t.Fatalf("Expected error for backend property %q with invalid type, got nil", tt.property)
			}
			if !strings.Contains(err.Error(), tt.property) {
				t.Errorf("Expected error to mention property %q, got: %s", tt.property, err.Error())
			}
		})
	}
}

// TestSendBackendRequestWithInvalidTimeoutType verifies that sendBackendRequest
// returns an error (rather than panicking with a nil-pointer dereference) when
// a timeout property is assigned a value of a non-RTIME type. The type guards
// run before any network request is issued, so no backend is contacted.
func TestSendBackendRequestWithInvalidTimeoutType(t *testing.T) {
	tests := []struct {
		name     string
		backend  *value.Backend
		property string
	}{
		{
			name: "first_byte_timeout must be RTIME",
			backend: newBackend("invalid_first_byte_timeout_type",
				backendProperty("first_byte_timeout", &ast.String{Value: "5s"}),
			),
			property: "first_byte_timeout",
		},
		{
			name: "fetch_timeout must be RTIME",
			backend: newBackend("invalid_fetch_timeout_type",
				backendProperty("fetch_timeout", &ast.Integer{Value: 5}),
			),
			property: "fetch_timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := New()
			ip.ctx = context.New()

			_, err := ip.sendBackendRequest(tt.backend)
			if err == nil {
				t.Fatalf("Expected error for backend property %q with invalid type, got nil", tt.property)
			}
			if !strings.Contains(err.Error(), tt.property) {
				t.Errorf("Expected error to mention property %q, got: %s", tt.property, err.Error())
			}
		})
	}
}


// buildOverride constructs an OverrideBackend from a raw headers map, running
// the same validation/parsing step that config.New performs at startup so the
// resulting entry mirrors what the interpreter would see in production.
func buildOverride(t *testing.T, host string, port int, headers map[string]string) *config.OverrideBackend {
	t.Helper()
	ob := &config.OverrideBackend{Host: host, Port: port, Headers: headers}
	// Access the unexported parseHeaders indirectly via config.New would be
	// overkill; instead we compile each template here using the same rules.
	if len(headers) > 0 {
		parsed := make([]config.OverrideHeader, 0, len(headers))
		for name, val := range headers {
			tmpl, err := config.ParseHeaderTemplate(val)
			if err != nil {
				t.Fatalf("ParseHeaderTemplate(%q) failed: %s", val, err)
			}
			parsed = append(parsed, config.OverrideHeader{Name: name, Value: tmpl})
		}
		ob.ParsedHeaders = parsed
	}
	return ob
}

// newInterpreterWithRequest returns an interpreter whose context has a request
// preconfigured with the given method/URL and optional inbound headers.
func newInterpreterWithRequest(method, url string, inbound map[string]string) *Interpreter {
	ip := New()
	ip.ctx = context.New()
	req := httptest.NewRequest(method, url, nil)
	for k, v := range inbound {
		req.Header.Set(k, v)
	}
	ip.ctx.Request = http.WrapRequest(req)
	return ip
}

// TestCreateBackendRequestInjectsOverrideHeaders exercises the header
// injection path added for the backend override feature. Each subtest builds
// a backend, configures an override entry, and asserts the resulting backend
// request carries the expected headers.
func TestCreateBackendRequestInjectsOverrideHeaders(t *testing.T) {
	backend := newBackend("bknd1",
		backendProperty("host", &ast.String{Value: "origin.example.com"}),
		backendProperty("port", &ast.String{Value: "80"}),
	)

	tests := []struct {
		name     string
		override *config.OverrideBackend
		inbound  map[string]string
		want     map[string]string
	}{
		{
			name: "backend.name and backend.host substitution",
			override: buildOverride(t, "127.0.0.1", 8000, map[string]string{
				"X-Backend-Name":  "${backend.name}",
				"X-Original-Host": "${backend.host}",
			}),
			want: map[string]string{
				"X-Backend-Name":  "bknd1",
				"X-Original-Host": "origin.example.com",
			},
		},
		{
			name: "literal value passes through",
			override: buildOverride(t, "127.0.0.1", 8000, map[string]string{
				"X-Token": "static-value",
			}),
			want: map[string]string{"X-Token": "static-value"},
		},
		{
			name: "set overwrites inbound header with same name",
			override: buildOverride(t, "127.0.0.1", 8000, map[string]string{
				"X-Token": "override",
			}),
			inbound: map[string]string{"X-Token": "inbound"},
			want:    map[string]string{"X-Token": "override"},
		},
		{
			name: "headers-only override still injects (no host/port change)",
			override: buildOverride(t, "", 0, map[string]string{
				"X-Backend-Name": "${backend.name}",
			}),
			want: map[string]string{"X-Backend-Name": "bknd1"},
		},
		{
			name: "escaped placeholder renders literally",
			override: buildOverride(t, "127.0.0.1", 8000, map[string]string{
				"X-Literal": "$${backend.name}",
			}),
			want: map[string]string{"X-Literal": "${backend.name}"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := newInterpreterWithRequest(ghttp.MethodGet, "http://example/test", tt.inbound)
			ip.ctx.OverrideBackends = map[string]*config.OverrideBackend{
				"bknd1": tt.override,
			}

			req, err := ip.createBackendRequest(ip.ctx, backend)
			if err != nil {
				t.Fatalf("createBackendRequest returned error: %s", err)
			}
			for name, want := range tt.want {
				if got := req.Header.Get(name); got != want {
					t.Errorf("header %q: got %q, want %q", name, got, want)
				}
			}
		})
	}
}

// TestCreateBackendRequestNoOverrideLeavesHeadersUntouched confirms that
// inbound headers are not modified (beyond the always-applied Fastly-FF
// header) when no override entry matches the backend.
func TestCreateBackendRequestNoOverrideLeavesHeadersUntouched(t *testing.T) {
	backend := newBackend("bknd1",
		backendProperty("host", &ast.String{Value: "origin.example.com"}),
		backendProperty("port", &ast.String{Value: "80"}),
	)
	ip := newInterpreterWithRequest(ghttp.MethodGet, "http://example/test", map[string]string{
		"X-Token": "inbound",
	})

	req, err := ip.createBackendRequest(ip.ctx, backend)
	if err != nil {
		t.Fatalf("createBackendRequest returned error: %s", err)
	}
	if got := req.Header.Get("X-Token"); got != "inbound" {
		t.Errorf("X-Token: got %q, want %q", got, "inbound")
	}
	if req.Header.Get("X-Backend-Name") != "" {
		t.Errorf("X-Backend-Name should not be set when no override is configured")
	}
}
