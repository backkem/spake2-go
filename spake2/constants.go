package spake2

import (
        "crypto/sha256"
        "hash"
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
        Group Group

        // Key derivation function
        KDF func(ikm, salt, info []byte, l int) []byte

        // Message authentication code
        MAC func(key, message []byte) []byte
}

// DefaultCiphersuite returns the default ciphersuite using P256 curve and SHA256
func DefaultCiphersuite() *Ciphersuite {
        return &Ciphersuite{
                Hash:  sha256.New,
                Group: P256Group(),
                KDF:   HKDF,
                MAC:   HMACSHA256,
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
