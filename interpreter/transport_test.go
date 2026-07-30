package interpreter

import (
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ysugimoto/falco/v2/ast"
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

// TestCreateBackendRequestHostHeader verifies which Host value the backend
// actually receives on the wire based on the .dynamic / .host_header /
// .always_use_host_header backend properties combined with the client's Host.
// The Host header must be set via req.Host rather than req.Header, because
// Go's net/http client uses req.Host (falling back to req.URL.Host) and
// ignores an entry in req.Header.
func TestCreateBackendRequestHostHeader(t *testing.T) {
	var received string
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		received = r.Host
		w.WriteHeader(stdhttp.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %s", err)
	}

	const clientHost = "client.example.com"

	tests := []struct {
		name  string
		extra []*ast.BackendProperty
		want  string
	}{
		{
			name: "dynamic true with host_header uses host_header",
			extra: []*ast.BackendProperty{
				backendProperty("dynamic", &ast.Boolean{Value: true}),
				backendProperty("host_header", &ast.String{Value: "custom.example.com"}),
			},
			want: "custom.example.com",
		},
		{
			name: "dynamic true without host_header uses client Host",
			extra: []*ast.BackendProperty{
				backendProperty("dynamic", &ast.Boolean{Value: true}),
			},
			want: clientHost,
		},
		{
			name: "dynamic false with host_header uses client Host",
			extra: []*ast.BackendProperty{
				backendProperty("dynamic", &ast.Boolean{Value: false}),
				backendProperty("host_header", &ast.String{Value: "custom.example.com"}),
			},
			want: clientHost,
		},
		{
			name: "always_use_host_header true uses backend host",
			extra: []*ast.BackendProperty{
				backendProperty("always_use_host_header", &ast.Boolean{Value: true}),
			},
			want: u.Hostname(),
		},
		{
			name: "always_use_host_header false uses client Host",
			extra: []*ast.BackendProperty{
				backendProperty("always_use_host_header", &ast.Boolean{Value: false}),
			},
			want: clientHost,
		},
		{
			name:  "no host-related property uses client Host",
			extra: nil,
			want:  clientHost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			received = ""
			props := append([]*ast.BackendProperty{
				backendProperty("host", &ast.String{Value: u.Hostname()}),
				backendProperty("port", &ast.String{Value: u.Port()}),
			}, tt.extra...)
			backend := newBackend("b", props...)

			ip := New()
			ip.ctx = context.New()
			incoming, err := stdhttp.NewRequest(stdhttp.MethodGet, "http://client/", nil)
			if err != nil {
				t.Fatalf("failed to build incoming request: %s", err)
			}
			// Mirror ProcessInit's behaviour of exposing the client Host via
			// the "Host" request header so that VCL's `req.http.host` reads it.
			incoming.Header.Set("Host", clientHost)
			ip.ctx.Request = http.WrapRequest(incoming)

			req, err := ip.createBackendRequest(ip.ctx, backend)
			if err != nil {
				t.Fatalf("createBackendRequest returned error: %s", err)
			}
			resp, err := http.SendRequest(req)
			if err != nil {
				t.Fatalf("SendRequest failed: %s", err)
			}
			resp.Body.Close()

			if received != tt.want {
				t.Errorf("Host header sent to backend = %q, want %q", received, tt.want)
			}
		})
	}
}

