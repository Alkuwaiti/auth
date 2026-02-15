// Package hasher provides a standard way to hash.
package hasher

import (
	"crypto/sha256"
	"encoding/hex"
)

type hasher struct{}

func NewHasher() hasher {
	return hasher{}
}

func (h hasher) Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func (h hasher) Compare(hashedInput, input string) bool {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:]) == hashedInput
}
