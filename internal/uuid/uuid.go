package uuid

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type UUID uuid.UUID

func (u UUID) UUID() uuid.UUID {
	return uuid.UUID(u)
}

func (u UUID) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

func (u *UUID) UnmarshalJSON(data []byte) error {
	id, err := uuid.Parse(string(data))
	if err != nil {
		return err
	}
	*u = UUID(id)
	return nil
}

func (u *UUID) UnmarshalParam(s string) error {
	id, err := Parse(s)
	if err != nil {
		return err
	}
	*u = UUID(id)
	return nil
}

func (u UUID) String() string {
	return u.UUID().String()
}

func New() (UUID, error) {
	id, err := uuid.NewRandom()
	return UUID(id), err
}

func MustNew() UUID {
	return Must(New())
}

func Ordered() (UUID, error) {
	id, err := uuid.NewV7()
	return UUID(id), err
}

func OrderedAt(at time.Time) (UUID, error) {
	uuid, err := New()
	if err != nil {
		return uuid, err
	}
	makeV7(at, uuid[:])
	return uuid, nil
}

// Copied from google uuid package
func makeV7(time time.Time, uuid []byte) {
	_ = uuid[15] // bounds check

	t, s := getV7Time(time)

	uuid[0] = byte(t >> 40)
	uuid[1] = byte(t >> 32)
	uuid[2] = byte(t >> 24)
	uuid[3] = byte(t >> 16)
	uuid[4] = byte(t >> 8)
	uuid[5] = byte(t)

	uuid[6] = 0x70 | (0x0F & byte(s>>8))
	uuid[7] = byte(s)
}

var lastV7time int64

const nanoPerMilli = 1000000

func getV7Time(t time.Time) (milli, seq int64) {
	nano := t.UnixNano()
	milli = nano / nanoPerMilli
	// Sequence number is between 0 and 3906 (nanoPerMilli>>8)
	seq = (nano - milli*nanoPerMilli) >> 8
	now := milli<<12 + seq
	if now <= lastV7time {
		now = lastV7time + 1
		milli = now >> 12
		seq = now & 0xfff
	}
	lastV7time = now
	return milli, seq
}

func MustOrdered() UUID {
	return Must(Ordered())
}

func Must(id UUID, err error) UUID {
	if err != nil {
		panic(err)
	}
	return id
}

func Parse(s string) (UUID, error) {
	id, err := uuid.Parse(s)
	return UUID(id), err
}

func Map(ids []UUID) []uuid.UUID {
	out := []uuid.UUID{}
	for _, id := range ids {
		out = append(out, id.UUID())
	}
	return out
}
