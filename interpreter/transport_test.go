package interpreter

import (
	nethttp "net/http"
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

// newTestContextWithRequest builds a *context.Context wired up with a minimal
// backend request source so that createBackendRequest can run to completion
// without panicking on nil fields.
func newTestContextWithRequest(t *testing.T) *context.Context {
	t.Helper()
	ctx := context.New()
	r, err := nethttp.NewRequest(nethttp.MethodGet, "http://client.example.com/", nil)
	if err != nil {
		t.Fatalf("Failed to build seed request: %s", err)
	}
	r.Host = "client.example.com"
	ctx.Request = http.WrapRequest(r)
	return ctx
}

// TestCreateBackendRequestHostHeader verifies that the HostHeader override
// takes precedence over the backend's host_header property when constructing
// the backend request, and that the backend's host_header property is used
// when the override is empty.
func TestCreateBackendRequestHostHeader(t *testing.T) {
	tests := []struct {
		name             string
		backend          *value.Backend
		overrideBackends map[string]*config.OverrideBackend
		expectedHost     string
	}{
		{
			name: "HostHeader override wins over backend host_header",
			backend: newBackend("api",
				backendProperty("host", &ast.String{Value: "origin.example.com"}),
				backendProperty("host_header", &ast.String{Value: "backend.example.com"}),
			),
			overrideBackends: map[string]*config.OverrideBackend{
				"api": {HostHeader: "override.example.com"},
			},
			expectedHost: "override.example.com",
		},
		{
			name: "empty HostHeader falls back to backend host_header",
			backend: newBackend("api",
				backendProperty("host", &ast.String{Value: "origin.example.com"}),
				backendProperty("host_header", &ast.String{Value: "backend.example.com"}),
			),
			overrideBackends: map[string]*config.OverrideBackend{
				"api": {Host: "override-host.example.com"},
			},
			expectedHost: "backend.example.com",
		},
		{
			name: "no host_header falls back to resolved host",
			backend: newBackend("api",
				backendProperty("host", &ast.String{Value: "origin.example.com"}),
			),
			overrideBackends: map[string]*config.OverrideBackend{
				"api": {Host: "override-host.example.com"},
			},
			expectedHost: "override-host.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := New()
			ip.ctx = newTestContextWithRequest(t)
			ip.ctx.OverrideBackends = tt.overrideBackends

			req, err := ip.createBackendRequest(ip.ctx, tt.backend)
			if err != nil {
				t.Fatalf("createBackendRequest returned error: %s", err)
			}
			if req.Host != tt.expectedHost {
				t.Errorf("Unexpected req.Host: expected %q, got %q", tt.expectedHost, req.Host)
			}
		})
	}
}

// TestCreateBackendRequestBackendNameHeader verifies that when BackendNameHeader
// is configured on the backend override, the resolved backend name is written
// to the specified header on the backend request; when empty, no such header
// is added.
func TestCreateBackendRequestBackendNameHeader(t *testing.T) {
	backend := newBackend("api",
		backendProperty("host", &ast.String{Value: "origin.example.com"}),
	)

	t.Run("BackendNameHeader sets header to backend name", func(t *testing.T) {
		ip := New()
		ip.ctx = newTestContextWithRequest(t)
		ip.ctx.OverrideBackends = map[string]*config.OverrideBackend{
			"api": {BackendNameHeader: "X-Selected-Backend"},
		}

		req, err := ip.createBackendRequest(ip.ctx, backend)
		if err != nil {
			t.Fatalf("createBackendRequest returned error: %s", err)
		}
		if got := req.Header.Get("X-Selected-Backend"); got != "api" {
			t.Errorf("Unexpected X-Selected-Backend header: expected %q, got %q", "api", got)
		}
	})

	t.Run("BackendNameHeader overwrites inbound value", func(t *testing.T) {
		ip := New()
		ip.ctx = newTestContextWithRequest(t)
		ip.ctx.Request.Header.Set("X-Selected-Backend", "stale-value")
		ip.ctx.OverrideBackends = map[string]*config.OverrideBackend{
			"api": {BackendNameHeader: "X-Selected-Backend"},
		}

		req, err := ip.createBackendRequest(ip.ctx, backend)
		if err != nil {
			t.Fatalf("createBackendRequest returned error: %s", err)
		}
		if got := req.Header.Get("X-Selected-Backend"); got != "api" {
			t.Errorf("Unexpected X-Selected-Backend header: expected %q, got %q", "api", got)
		}
	})

	t.Run("empty BackendNameHeader adds no header", func(t *testing.T) {
		ip := New()
		ip.ctx = newTestContextWithRequest(t)
		ip.ctx.OverrideBackends = map[string]*config.OverrideBackend{
			"api": {},
		}

		req, err := ip.createBackendRequest(ip.ctx, backend)
		if err != nil {
			t.Fatalf("createBackendRequest returned error: %s", err)
		}
		if got := req.Header.Get("X-Selected-Backend"); got != "" {
			t.Errorf("Expected no X-Selected-Backend header, got %q", got)
		}
	})
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
