package config

import (
	"regexp"

	"github.com/pkg/errors"
)

// validOverrideHeaderName mirrors the character set and length limit used by
// interpreter/function/shared.IsValidHeader, i.e. Fastly's documented header
// name rules (https://developer.fastly.com/reference/vcl/functions/headers/header-set/#header-names).
// It is duplicated here rather than imported to avoid a config -> interpreter
// dependency; the two must be kept in sync.
var validOverrideHeaderName = regexp.MustCompile("^[!#$%&'*+-.0-9A-Z^_`a-z|~:]{1,126}$")

// parseHeaders validates every entry in Headers and populates ParsedHeaders.
// It is intended to be called exactly once, at config load time, so that
// invalid header names or malformed value templates are surfaced as startup
// errors rather than per-request failures.
func (o *OverrideBackend) parseHeaders() error {
	if len(o.Headers) == 0 {
		o.ParsedHeaders = nil
		return nil
	}
	parsed := make([]OverrideHeader, 0, len(o.Headers))
	for name, value := range o.Headers {
		if name == "" {
			return errors.Errorf("override_backends: header name must not be empty")
		}
		if !validOverrideHeaderName.MatchString(name) {
			return errors.Errorf(
				"override_backends: invalid header name %q", name,
			)
		}
		tmpl, err := ParseHeaderTemplate(value)
		if err != nil {
			return errors.Wrapf(err, "override_backends: header %q", name)
		}
		parsed = append(parsed, OverrideHeader{Name: name, Value: tmpl})
	}
	o.ParsedHeaders = parsed
	return nil
}
