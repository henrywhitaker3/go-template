package uuid

import (
	"encoding/json"

	"github.com/google/uuid"
)

type UUID uuid.UUID

func (u UUID) UUID() uuid.UUID {
	return uuid.UUID(u)
}

func (u UUID) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.UUID().String())
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
