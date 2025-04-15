package uuid

import (
	"slices"
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

func FuzzNoCollisions(f *testing.F) {
	generated := map[UUID]struct{}{}

	f.Fuzz(func(t *testing.T, _ string) {
		id := Must(OrderedAt(time.Now()))
		if _, ok := generated[id]; ok {
			t.Fail()
		}
		generated[id] = struct{}{}
	})
}

func TestItOrderV7AtCorrectly(t *testing.T) {
	first := time.Now().Add(-time.Minute)
	last := time.Now()

	firstId := Must(OrderedAt(first))
	lastId := Must(OrderedAt(last))

	ids := []string{lastId.String(), firstId.String()}

	slices.Sort(ids)

	require.Equal(t, firstId.String(), ids[0])
	require.Equal(t, lastId.String(), ids[1])
}
