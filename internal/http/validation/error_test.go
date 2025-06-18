package validation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestItMarshalsErrors(t *testing.T) {
	errObj := Build().With("bongo", "required field").
		With("another", "too long")

	by, err := json.Marshal(errObj)
	require.Nil(t, err)

	require.Equal(
		t,
		`{"another":"too long","bongo":"required field"}`,
		string(by),
	)
}
