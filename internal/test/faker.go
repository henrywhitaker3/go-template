package test

import "github.com/brianvoe/gofakeit/v7"

func init() {
	gofakeit.Seed(0)
}

func Word() string {
	return gofakeit.Word()
}

func Sentence(words int) string {
	return gofakeit.Sentence(words)
}

func Email() string {
	return gofakeit.Email()
}

func Letters(length int) string {
	return gofakeit.LetterN(uint(length))
}

func Name() string {
	return gofakeit.Name()
}
