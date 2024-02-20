// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/gobwas/glob"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Querystring_globfilter_except_Name = "querystring.globfilter_except"

var Querystring_globfilter_except_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Querystring_globfilter_except_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Querystring_globfilter_except_Name, 2, args)
	}
	for i := range args {
		if args[i].Type() != Querystring_globfilter_except_ArgumentTypes[i] {
			return errors.TypeMismatch(Querystring_globfilter_except_Name, i+1, Querystring_globfilter_except_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of querystring.globfilter_except
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/query-string/querystring-globfilter-except/
func Querystring_globfilter_except(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Querystring_globfilter_except_Validate(args); err != nil {
		return value.Null, err
	}

	v := value.Unwrap[*value.String](args[0])
	name := value.Unwrap[*value.String](args[1])

	pattern, err := glob.Compile(name.Value)
	if err != nil {
		return value.Null, errors.New(
			Querystring_globfilter_Name, "Invalid glob filter string: %s, error: %s", v.Value, err.Error(),
		)
	}

	result := shared.QueryStringFilter(v.Value, func(v string) bool {
		return pattern.Match(v)
	})
	return &value.String{Value: result}, nil
}
