package validation

import (
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

type Validator struct {
	v *validator.Validate
}

func New(options ...validator.Option) *Validator {
	if len(options) == 0 {
		options = append(options, validator.WithRequiredStructEnabled())
	}

	v := validator.New(options...)
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	return &Validator{
		v: v,
	}
}

func (v *Validator) Validate(req any) error {
	if req == nil {
		return nil
	}

	err := v.v.Struct(req)
	if err == nil {
		return nil
	}

	vErr, ok := err.(validator.ValidationErrors)
	if !ok {
		return err
	}

	if len(vErr) == 0 {
		return nil
	}

	out := Build()
	for _, ve := range vErr {
		out = out.With(ve.Field(), ve.Tag())
	}

	return out
}
