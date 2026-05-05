package utils

import "math/rand"

func GenerateID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 8

	id := make([]byte, length)
	for i := range id {
		id[i] = charset[rand.Intn(len(charset))]
	}
	return string(id)
}
