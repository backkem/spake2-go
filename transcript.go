package spake2

import (
	"encoding/binary"
)

// Transcript represents the protocol transcript used to derive keys
type Transcript struct {
	IdentityA []byte
	IdentityB []byte
	MessageA  []byte
	MessageB  []byte
	K         []byte
	Password  []byte
	AAD       []byte
}

// NewTranscript creates a new protocol transcript
func NewTranscript(identityA, identityB, messageA, messageB, k []byte, password []byte, aad []byte) *Transcript {
	return &Transcript{
		IdentityA: identityA,
		IdentityB: identityB,
		MessageA:  messageA,
		MessageB:  messageB,
		K:         k,
		Password:  password,
		AAD:       aad,
	}
}

// Bytes returns the byte representation of the transcript as specified in RFC 9382
//
//	 TT = len(A)  || A
//		|| len(B)  || B
//		|| len(pA) || pA
//		|| len(pB) || pB
//		|| len(K)  || K
//		|| len(w)  || w
func (t *Transcript) Bytes() []byte {
	var transcript []byte

	// Encode Identity A
	transcript = append(transcript, encodeLength(t.IdentityA)...)
	transcript = append(transcript, t.IdentityA...)

	// Encode Identity B
	transcript = append(transcript, encodeLength(t.IdentityB)...)
	transcript = append(transcript, t.IdentityB...)

	// Encode Message A (pA)
	transcript = append(transcript, encodeLength(t.MessageA)...)
	transcript = append(transcript, t.MessageA...)

	// Encode Message B (pB)
	transcript = append(transcript, encodeLength(t.MessageB)...)
	transcript = append(transcript, t.MessageB...)

	// Encode K
	transcript = append(transcript, encodeLength(t.K)...)
	transcript = append(transcript, t.K...)

	// Encode Password (w)
	transcript = append(transcript, encodeLength(t.Password)...)
	transcript = append(transcript, t.Password...)

	// If we have AAD, add it too
	if len(t.AAD) > 0 {
		transcript = append(transcript, encodeLength(t.AAD)...)
		transcript = append(transcript, t.AAD...)
	}

	return transcript
}

// encodeLength encodes the length of a byte array as a little-endian 8-byte number
func encodeLength(data []byte) []byte {
	length := make([]byte, 8)
	binary.LittleEndian.PutUint64(length, uint64(len(data)))
	return length
}
