package uuid

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestItMakesV7satTime(t *testing.T) {
	now := time.Now().Add(-time.Minute * 5)

	one := Must(OrderedAt(now))
	two := Must(OrderedAt(now))

	t.Log(one.String())
	t.Log(two.String())

	t.Log(one[0:8])
	t.Log(two[0:8])

	for i := range 8 {
		if i < 7 {
			require.Equal(t, one[i], two[i], "index %d is not equal", i)
		}
		if i == 7 {
			require.Equal(t, int(one[i])+1, int(two[i]))
		}
	}

	require.NotEqual(t, one, two)
}
