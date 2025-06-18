package validation

import "encoding/json"

type ValidationError struct {
	errors map[string]string
}

func Build() *ValidationError {
	return &ValidationError{
		errors: map[string]string{},
	}
}

func (v *ValidationError) With(field string, message string) *ValidationError {
	v.errors[field] = message
	return v
}

func (v *ValidationError) Error() string {
	return "not implemented yet"
}

func (v ValidationError) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.errors)
}
