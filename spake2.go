package spake2

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/backkem/spake2-go/internal/crypto"
	"go.dedis.ch/kyber/v4"
)

var (
	// ErrInvalidMessage indicates that the received message is invalid
	ErrInvalidMessage = errors.New("invalid message format")

	// ErrInvalidConfirmation indicates that the confirmation message is invalid
	ErrInvalidConfirmation = errors.New("invalid confirmation message")

	// ErrProtocolIncomplete indicates that the protocol is not completed yet
	ErrProtocolIncomplete = errors.New("protocol not completed")

	// ErrPasswordMismatch indicates that the calculated shared secret doesn't match
	ErrPasswordMismatch = errors.New("password mismatch")
)

// State represents the protocol state
type State int

const (
	// StateInitial is the initial state
	StateInitial State = iota

	// StateStarted means the first message has been sent/received
	StateStarted

	// StateFinished means all messages have been processed
	StateFinished

	// StateConfirmed means key confirmation has been performed
	StateConfirmed
)

// SPAKE2 implements the SPAKE2 password-authenticated key exchange protocol
type SPAKE2 struct {
	// Configuration options
	options *Options

	// The current protocol state
	state State

	// The role of this instance (ProtocolRoleClient or ProtocolRoleServer)
	role string

	// The scalar value (x for client, y for server)
	scalar kyber.Scalar

	// The password converted to a scalar
	password kyber.Scalar

	// The transcript of the protocol
	transcript *Transcript

	// The derived keys
	sharedKey   []byte // Ke
	confirmKeyA []byte // KcA
	confirmKeyB []byte // KcB

	// Storage for debugging
	dbgTT      []byte
	dbgAuthKey []byte
	dbgHash    []byte
}

// NewClient creates a new SPAKE2 client (party A)
func NewClient(password []byte, options *Options) *SPAKE2 {
	if options == nil {
		options = DefaultOptions()
	}

	w := derivePassword(password, options.Ciphersuite)

	return &SPAKE2{
		options:  options,
		state:    StateInitial,
		role:     ProtocolRoleClient,
		password: w,
	}
}

// NewServer creates a new SPAKE2 server (party B)
func NewServer(password []byte, options *Options) *SPAKE2 {
	if options == nil {
		options = DefaultOptions()
	}

	w := derivePassword(password, options.Ciphersuite)

	return &SPAKE2{
		options:  options,
		state:    StateInitial,
		role:     ProtocolRoleServer,
		password: w,
	}
}

// derivePassword converts a password to a scalar suitable for use in the protocol
func derivePassword(password []byte, ciphersuite *Ciphersuite) kyber.Scalar {
	// w = MHF(pw) mod p

	h := ciphersuite.Hash()
	h.Write(password)
	digest := h.Sum(nil)

	// Convert to integer modulo the group order
	return ciphersuite.Group.Scalar().SetBytes(digest)
}

// Start initiates the protocol for the client (A) and returns the first message
func (s *SPAKE2) Start() ([]byte, error) {
	if s.role != ProtocolRoleClient {
		return nil, fmt.Errorf("only client can start the protocol")
	}

	if s.state != StateInitial {
		return nil, fmt.Errorf("protocol already started")
	}

	group := s.options.Ciphersuite.Group

	// Generate random scalar x
	if !s.options.dbg {
		s.scalar = group.RandomScalar()
	}

	// Get the appropriate constants M, N
	m, _, err := generateMN(group, s.options.SymmetricMode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate M: %w", err)
	}

	// Compute X = x*P
	gen, err := group.Generator()
	if err != nil {
		return nil, fmt.Errorf("failed to get generator: %w", err)
	}
	x := group.Point().Mul(s.scalar, gen)

	// Compute pA = w*M + X
	wm := group.Point().Mul(s.password, m)
	pA := group.Point().Add(wm, x)

	// Serialize pA
	message, err := crypto.PointToBytes(pA)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pA: %w", err)
	}

	s.state = StateStarted

	return message, nil
}

// Compute shared group element K = h * y * (pA - w * M)
// Construct transcript TT = len(A) || A || len(B) || B || len(pA) || pA || len(pB) || pB || len(K) || K || len(w) || w
// Compute Hash(TT) = Ke || Ka, where |Ke| = |Ka| = half of hash output length (e.g., 128 bits for SHA-256)
// Compute KcA || KcB = KDF(Ka, nil, "ConfirmationKeys" || AAD, L), where L = 2 * |KcB|, AAD is optional
// Compute confirmation message cB = MAC(KcB, TT)
// Send cB to A
// Output Ke as the shared secret after receiving and verifying cA

// Exchange processes the client's message and generates the server's response
func (s *SPAKE2) Exchange(clientMessage []byte) ([]byte, error) {
	if s.role != ProtocolRoleServer {
		return nil, fmt.Errorf("only server can exchange messages")
	}

	if s.state != StateInitial {
		return nil, fmt.Errorf("protocol already started")
	}

	group := s.options.Ciphersuite.Group

	// Parse client's message pA
	pA, err := crypto.PointFromBytes(group, clientMessage)
	if err != nil {
		return nil, fmt.Errorf("invalid client message: %v", err)
	}

	// Generate random scalar y
	if !s.options.dbg {
		s.scalar = group.RandomScalar()
	}

	// Get the appropriate constants M, N
	m, n, err := generateMN(group, s.options.SymmetricMode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate n/m: %v", err)
	}

	gen, err := group.Generator()
	if err != nil {
		return nil, fmt.Errorf("failed to get generator point: %v", err)
	}

	// Compute Y = y*P
	y := group.Point().Mul(s.scalar, gen)

	// Compute pB = w*N + Y
	wn := group.Point().Mul(s.password, n)
	pB := group.Point().Add(wn, y)

	// Compute K = h * y * (pA - w * M)
	// For P-256: h = 1
	wm := group.Point().Mul(s.password, m)
	pAminusWm := group.Point().Sub(pA, wm)
	k := group.Point().Mul(s.scalar, pAminusWm)

	// Store the protocol transcript
	pBData, err := crypto.PointToBytes(pB)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pB: %v", err)
	}
	kData, err := crypto.PointToBytes(k)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal k: %v", err)
	}
	passData, err := s.password.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal password: %v", err)
	}
	s.transcript = NewTranscript(
		s.options.IdentityA,
		s.options.IdentityB,
		clientMessage,
		pBData,
		kData,
		passData,
		s.options.AAD,
	)

	// Derive the keys
	s.deriveKeys()

	s.state = StateStarted

	// Return pB
	return pBData, nil
}

// Compute shared group element
//  Construct transcript
//  Compute Hash(TT) = Ke || Ka, where |Ke| = |Ka| = half of hash output length (e.g., 128 bits for SHA-256)
//  Compute KcA || KcB = KDF(Ka, nil, "ConfirmationKeys" || AAD, L), where L = 2 * |KcA|, AAD is optional
//  Compute confirmation message cA = MAC(KcA, TT)
//  Send cA to B
//  Output Ke as the shared secret after receiving and verifying cB

// Finish processes the server's message for the client and returns the confirmation message
func (s *SPAKE2) Finish(serverMessage []byte) ([]byte, error) {
	if s.role != ProtocolRoleClient {
		return nil, fmt.Errorf("only client can finish the protocol")
	}

	if s.state != StateStarted {
		return nil, fmt.Errorf("protocol not started")
	}

	group := s.options.Ciphersuite.Group

	// Parse server's message pB
	pB, err := crypto.PointFromBytes(group, serverMessage)
	if err != nil {
		return nil, fmt.Errorf("invalid server message: %w", err)
	}

	_, n, err := generateMN(group, s.options.SymmetricMode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate n/m: %v", err)
	}

	// K = h * x * (pB - w * N)
	// For P-256: h = 1

	// Calculate K = h*x*(pB - w*N)
	wn := group.Point().Mul(s.password, n)

	// Subtract w*N from pB
	pBminusWn := group.Point().Sub(pB, wn)

	// Multiply by h*x
	// Simplified: we're assuming h=1 for curves where the cofactor is 1
	k := group.Point().Mul(s.scalar, pBminusWn)

	// Store the protocol transcript

	initData, err := s.generateInitialMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to generate initial message: %v", err)
	}
	kData, err := crypto.PointToBytes(k)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal k: %v", err)
	}
	passData, err := s.password.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal password: %v", err)
	}
	s.transcript = NewTranscript(
		s.options.IdentityA,
		s.options.IdentityB,
		initData,
		serverMessage,
		kData,
		passData,
		s.options.AAD,
	)

	// Derive the keys
	s.deriveKeys()

	// cA = MAC(KcA, TT)
	tt := s.transcript.Bytes()
	confirmationA := s.options.Ciphersuite.MAC(s.confirmKeyA, tt)

	s.state = StateFinished

	return confirmationA, nil
}

// Confirm processes the client's confirmation message and returns the server's confirmation
func (s *SPAKE2) Confirm(clientConfirmation []byte) ([]byte, error) {
	if s.role != ProtocolRoleServer {
		return nil, fmt.Errorf("only server can confirm")
	}

	if s.state != StateStarted {
		return nil, fmt.Errorf("protocol not completed")
	}

	// cA = MAC(KcA, TT)
	tt := s.transcript.Bytes()
	expectedConfirmation := s.options.Ciphersuite.MAC(
		s.confirmKeyA,
		tt,
	)

	if subtle.ConstantTimeCompare(clientConfirmation, expectedConfirmation) != 1 {
		return nil, ErrInvalidConfirmation
	}

	// cB = MAC(KcB, TT)
	confirmationB := s.options.Ciphersuite.MAC(
		s.confirmKeyB,
		tt,
	)

	s.state = StateConfirmed

	return confirmationB, nil
}

// Verify verifies the server's confirmation message for the client
func (s *SPAKE2) Verify(serverConfirmation []byte) error {
	if s.role != ProtocolRoleClient {
		return fmt.Errorf("only client can verify server confirmation")
	}

	if s.state != StateFinished {
		return fmt.Errorf("protocol not completed")
	}

	// cB = MAC(KcB, TT)
	tt := s.transcript.Bytes()
	expectedConfirmation := s.options.Ciphersuite.MAC(
		s.confirmKeyB,
		tt,
	)

	if subtle.ConstantTimeCompare(serverConfirmation, expectedConfirmation) != 1 {
		return ErrInvalidConfirmation
	}

	s.state = StateConfirmed

	return nil
}

// SharedKey returns the derived shared key
func (s *SPAKE2) SharedKey() ([]byte, error) {
	if s.state < StateConfirmed {
		return nil, fmt.Errorf("can't get shared key before confirmation")
	}

	return s.sharedKey, nil
}

// deriveKeys derives the shared keys from the transcript
func (s *SPAKE2) deriveKeys() {
	// Get the transcript bytes using the exact RFC format
	transcript := s.transcript.Bytes()

	// Compute Hash(TT) = Ke || Ka
	//   where |Ke| = |Ka| = half of hash output length (e.g., 128 bits for SHA-256)
	h := s.options.Ciphersuite.Hash()
	h.Write(transcript)
	transcriptHash := h.Sum(nil)

	hashLen := len(transcriptHash)
	halfLen := hashLen / 2

	// Ke: sharedKey
	s.sharedKey = transcriptHash[:halfLen]
	// Ke: authKey
	authKey := transcriptHash[halfLen:]

	// Compute KcA || KcB = KDF(Ka, nil, "ConfirmationKeys" || AAD, L), where L = 2 * |KcB|, AAD is optional
	payload := append([]byte("ConfirmationKeys"), s.options.AAD...)
	kc := s.options.Ciphersuite.KDF(authKey, nil, payload, 256/8)
	halfLen = 128 / 8
	s.confirmKeyA = kc[:halfLen]
	s.confirmKeyB = kc[halfLen:]

	if s.options.dbg {
		s.dbgTT = transcript
		s.dbgHash = transcriptHash
		s.dbgAuthKey = authKey
	}
}

// generateInitialMessage regenerates the initial message for the client
// This is used to create the transcript when finishing the protocol
func (s *SPAKE2) generateInitialMessage() ([]byte, error) {
	group := s.options.Ciphersuite.Group

	// Get the appropriate constants M, N
	m, _, err := generateMN(group, s.options.SymmetricMode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate n/m: %v", err)
	}

	// Calculate X = x*P
	gen, err := group.Generator()
	if err != nil {
		return nil, fmt.Errorf("failed to get generator: %v", err)
	}
	x := group.Point().Mul(s.scalar, gen)

	// Calculate pA = w*M + X
	wm := group.Point().Mul(s.password, m)
	pA := group.Point().Add(wm, x)

	// Serialize pA
	pAData, err := pA.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pA: %v", err)
	}
	return pAData, nil
}
