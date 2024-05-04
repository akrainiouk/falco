package ast

import (
	"fmt"
	"strings"
)

type Ident struct {
	*Meta
	Value string
}

func (i *Ident) expression()    {}
func (i *Ident) GetMeta() *Meta { return i.Meta }
func (i *Ident) String() string {
	return strings.TrimSpace(i.LeadingComment(inline) + i.Value + i.TrailingComment(inline))
}

type IP struct {
	*Meta
	Value string
}

func (i *IP) expression()    {}
func (i *IP) GetMeta() *Meta { return i.Meta }
func (i *IP) String() string {
	return strings.TrimSpace(i.LeadingComment(inline) + i.Value + i.TrailingComment(inline))
}

type Boolean struct {
	*Meta
	Value bool
}

func (b *Boolean) expression()    {}
func (b *Boolean) GetMeta() *Meta { return b.Meta }
func (b *Boolean) String() string {
	return strings.TrimSpace(
		fmt.Sprintf("%s%t%s", b.LeadingComment(inline), b.Value, b.TrailingComment(inline)),
	)
}

type Integer struct {
	*Meta
	Value int64
}

func (i *Integer) expression()    {}
func (i *Integer) GetMeta() *Meta { return i.Meta }
func (i *Integer) String() string {
	return strings.TrimSpace(
		fmt.Sprintf("%s%d%s", i.LeadingComment(inline), i.Value, i.TrailingComment(inline)),
	)
}

type String struct {
	*Meta
	Value string
}

func (s *String) expression()    {}
func (s *String) GetMeta() *Meta { return s.Meta }
func (s *String) String() string {
	if s.Token.Offset == 4 { // offset=4 means bracket string
		return strings.TrimSpace(
			fmt.Sprintf(`%s{"%s"}%s`, s.LeadingComment(inline), s.Value, s.TrailingComment(inline)),
		)
	}
	return strings.TrimSpace(
		fmt.Sprintf(`%s"%s"%s`, s.LeadingComment(inline), s.Value, s.TrailingComment(inline)),
	)
}

type Float struct {
	*Meta
	Value float64
}

func (f *Float) expression()    {}
func (f *Float) GetMeta() *Meta { return f.Meta }
func (f *Float) String() string {
	return strings.TrimSpace(
		fmt.Sprintf(`%s%f%s`, f.LeadingComment(inline), f.Value, f.TrailingComment(inline)),
	)
}

type RTime struct {
	*Meta
	Value string
}

func (r *RTime) expression()    {}
func (r *RTime) GetMeta() *Meta { return r.Meta }
func (r *RTime) String() string {
	return strings.TrimSpace(r.LeadingComment(inline) + r.Value + r.TrailingComment(inline))
}
