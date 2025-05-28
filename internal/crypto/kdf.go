package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"math/big"
)

// HKDF implements the HMAC-based Extract-and-Expand Key Derivation Function
// as defined in RFC 5869, using the provided hash function.
func HKDF(ikm, salt, info []byte, length int) []byte {
	// Extract
	hash := sha256.New
	prk := hkdfExtract(hash, ikm, salt)

	// Expand
	return hkdfExpand(hash, prk, info, length)
}

// hkdfExtract performs the HKDF extract operation
func hkdfExtract(hashFunc func() hash.Hash, ikm, salt []byte) []byte {
	if salt == nil || len(salt) == 0 {
		salt = make([]byte, hashFunc().Size())
	}
	extractor := hmac.New(hashFunc, salt)
	extractor.Write(ikm)
	return extractor.Sum(nil)
}

// hkdfExpand performs the HKDF expand operation
func hkdfExpand(hashFunc func() hash.Hash, prk, info []byte, length int) []byte {
	hashSize := hashFunc().Size()
	blocks := (length + hashSize - 1) / hashSize
	output := make([]byte, 0, blocks*hashSize)

	prev := []byte{}
	for i := 0; i < blocks; i++ {
		h := hmac.New(hashFunc, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{byte(i + 1)})
		prev = h.Sum(nil)
		output = append(output, prev...)
	}

	return output[:length]
}

// HMACSHA256 implements the HMAC-SHA256 Message Authentication Code
func HMACSHA256(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

// randomInt generates a random integer in the range [0, max)
func randomInt(max *big.Int) (*big.Int, error) {
	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// constantTimeCompare compares two byte slices in constant time
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result uint8
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
