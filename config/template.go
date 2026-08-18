package config

import (
	"strings"

	"github.com/pkg/errors"
)

// SupportedHeaderTemplateVariables enumerates every variable name that is
// allowed inside a ${...} placeholder in an override header value. Keeping the
// list closed lets us reject typos at config load time instead of silently
// producing empty values at request time.
var SupportedHeaderTemplateVariables = map[string]struct{}{
	"backend.name": {},
	"backend.host": {},
}

// HeaderTemplate is the parsed form of an override header value. It is a flat
// sequence of literal and variable-reference parts, evaluated left to right
// against a variable map supplied by the interpreter.
type HeaderTemplate []headerTemplatePart

type headerTemplatePart struct {
	// isVar distinguishes a variable reference from a literal fragment.
	isVar bool
	// text holds the literal text (when !isVar) or the variable name
	// (when isVar), already trimmed of surrounding whitespace.
	text string
}

// ParseHeaderTemplate parses a header value string using the following rules:
//
//   - "${name}" is a placeholder. name is trimmed of leading/trailing
//     whitespace and must appear in SupportedHeaderTemplateVariables.
//   - "$$" is an escape sequence that renders as a single literal "$".
//   - A lone "$" not followed by "{" is a literal "$".
//   - An unterminated "${" (no closing "}") or an empty/unknown variable
//     name is an error.
func ParseHeaderTemplate(s string) (HeaderTemplate, error) {
	var (
		parts   HeaderTemplate
		literal strings.Builder
	)
	flushLiteral := func() {
		if literal.Len() > 0 {
			parts = append(parts, headerTemplatePart{text: literal.String()})
			literal.Reset()
		}
	}

	for i := 0; i < len(s); {
		c := s[i]
		if c != '$' {
			literal.WriteByte(c)
			i++
			continue
		}
		// c == '$': look ahead to classify.
		if i+1 < len(s) && s[i+1] == '$' {
			// "$$" -> literal "$"
			literal.WriteByte('$')
			i += 2
			continue
		}
		if i+1 >= len(s) || s[i+1] != '{' {
			// Lone "$" not followed by "{" or "$": literal "$".
			literal.WriteByte('$')
			i++
			continue
		}
		// "${" starts a placeholder. Find matching "}".
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			return nil, errors.Errorf(
				"malformed header value template %q: unterminated placeholder starting at offset %d",
				s, i,
			)
		}
		name := strings.TrimSpace(s[i+2 : i+2+end])
		if name == "" {
			return nil, errors.Errorf(
				"malformed header value template %q: empty placeholder at offset %d",
				s, i,
			)
		}
		if _, ok := SupportedHeaderTemplateVariables[name]; !ok {
			return nil, errors.Errorf(
				"malformed header value template %q: unsupported variable %q at offset %d",
				s, name, i,
			)
		}
		flushLiteral()
		parts = append(parts, headerTemplatePart{isVar: true, text: name})
		i += 2 + end + 1
	}
	flushLiteral()
	return parts, nil
}

// Render evaluates the template against the given variables and returns the
// resulting header value. Callers are expected to supply values for every
// variable listed in SupportedHeaderTemplateVariables; a missing entry
// renders as an empty string.
func (t HeaderTemplate) Render(vars map[string]string) string {
	var b strings.Builder
	for _, p := range t {
		if p.isVar {
			b.WriteString(vars[p.text])
		} else {
			b.WriteString(p.text)
		}
	}
	return b.String()
}
