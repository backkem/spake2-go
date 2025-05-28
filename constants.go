package spake2

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"hash"

	"github.com/backkem/spake2/internal/crypto"
	"go.dedis.ch/kyber/v4"
)

const (
	P256_M_HEX = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
	P256_N_HEX = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
)

const (
	// DefaultKeySize is the default key size for derived keys
	DefaultKeySize = 32

	// ProtocolRoleClient represents the "A" role in the SPAKE2 protocol
	ProtocolRoleClient = "A"

	// ProtocolRoleServer represents the "B" role in the SPAKE2 protocol
	ProtocolRoleServer = "B"
)

// Ciphersuite represents a complete set of algorithms for the SPAKE2 protocol
type Ciphersuite struct {
	// Hash function used in the protocol
	Hash func() hash.Hash

	// Group specific operations
	Group crypto.Group

	// Key derivation function
	KDF func(ikm, salt, info []byte, l int) []byte

	// Message authentication code
	MAC func(key, message []byte) []byte
}

// DefaultCiphersuite returns the default ciphersuite using P256 curve and SHA256
func DefaultCiphersuite() *Ciphersuite {
	return &Ciphersuite{
		Hash:  sha256.New,
		Group: crypto.P256Group(),
		KDF:   crypto.HKDF,
		MAC:   crypto.HMACSHA256,
	}
}

// Options represents configuration options for SPAKE2 protocol
type Options struct {
	// The ciphersuite to use
	Ciphersuite *Ciphersuite

	// Identity of party A (client)
	IdentityA []byte

	// Identity of party B (server)
	IdentityB []byte

	// Additional authenticated data
	AAD []byte

	// Whether to use the symmetric variant with M=N
	SymmetricMode bool

	// Enables debugging; avoid randomness and stores intermediary results.
	dbg bool
}

// DefaultOptions returns the default options for SPAKE2
func DefaultOptions() *Options {
	return &Options{
		Ciphersuite:   DefaultCiphersuite(),
		IdentityA:     []byte(ProtocolRoleClient),
		IdentityB:     []byte(ProtocolRoleServer),
		AAD:           nil,
		SymmetricMode: false,
	}
}

func generateMN(c crypto.Group, symmetric bool) (kyber.Point, kyber.Point, error) {
	m, err := generateM(c)
	if err != nil {
		return nil, nil, err
	}
	if symmetric {
		return m, m, nil
	}
	n, err := generateN(c)
	if err != nil {
		return nil, nil, err
	}
	return m, n, nil
}

// generateM generates the M point for a given curve
func generateM(c crypto.Group) (kyber.Point, error) {
	mCompressed, err := hex.DecodeString(P256_M_HEX)
	if err != nil {
		return nil, err
	}
	return parsePointCompressed(c, mCompressed)
}

// generateN generates the N point for a given curve
func generateN(c crypto.Group) (kyber.Point, error) {
	nCompressed, err := hex.DecodeString(P256_N_HEX)
	if err != nil {
		return nil, err
	}
	return parsePointCompressed(c, nCompressed)
}

func parsePointCompressed(c crypto.Group, compressed []byte) (kyber.Point, error) {
	x, y := elliptic.UnmarshalCompressed(c.Curve(), compressed)
	p, err := crypto.NewPoint(c, x, y)
	if err != nil {
		return nil, err
	}
	return p, nil
}
