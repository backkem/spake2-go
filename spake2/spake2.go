package spake2

import (
        "errors"
        "fmt"
        "math/big"
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
        scalar *big.Int
        
        // The password converted to a scalar
        password *big.Int
        
        // The transcript of the protocol
        transcript *Transcript
        
        // The derived keys
        sharedKey   []byte // Ke
        confirmKeyA []byte // KcA
        confirmKeyB []byte // KcB
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
func derivePassword(password []byte, ciphersuite *Ciphersuite) *big.Int {
        // This is a simplified approach; a production implementation should use a memory-hard function
        // as recommended in the RFC
        h := ciphersuite.Hash()
        h.Write(password)
        digest := h.Sum(nil)
        
        // Convert to integer modulo the group order
        result := new(big.Int).SetBytes(digest)
        return result.Mod(result, ciphersuite.Group.Order())
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
        var err error
        s.scalar, err = group.RandomScalar()
        if err != nil {
                return nil, fmt.Errorf("failed to generate random scalar: %w", err)
        }
        
        // Get the appropriate constants M, N
        m, _ := group.GetConstants(s.options.SymmetricMode)
        
        // Calculate X = x*P
        gen := group.Generator()
        x := group.ScalarMult(gen, s.scalar)
        
        // Calculate pA = w*M + X
        wm := group.ScalarMult(m, s.password)
        pA := group.Add(wm, x)
        
        // Serialize pA
        message := group.ElementToBytes(pA)
        
        s.state = StateStarted
        
        return message, nil
}

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
        pA, err := group.ElementFromBytes(clientMessage)
        if err != nil {
                return nil, fmt.Errorf("invalid client message: %w", err)
        }
        
        // Generate random scalar y
        s.scalar, err = group.RandomScalar()
        if err != nil {
                return nil, fmt.Errorf("failed to generate random scalar: %w", err)
        }
        
        // Get the appropriate constants M, N
        _, n := group.GetConstants(s.options.SymmetricMode)
        
        // Calculate Y = y*P
        gen := group.Generator()
        y := group.ScalarMult(gen, s.scalar)
        
        // Calculate pB = w*N + Y
        wn := group.ScalarMult(n, s.password)
        pB := group.Add(wn, y)
        
        // Calculate K = h*y*(pA - w*M)
        m, _ := group.GetConstants(s.options.SymmetricMode)
        wm := group.ScalarMult(m, s.password)
        
        // Subtract w*M from pA
        // In additive notation, we need to add the negative of wm
        // We're using a simplified approach here
        negWm := group.ScalarMult(wm, new(big.Int).Sub(big.NewInt(0), big.NewInt(1)))
        pAminusWm := group.Add(pA, negWm)
        
        // Multiply by h*y
        // Simplified: we're assuming h=1 for curves where the cofactor is 1
        k := group.ScalarMult(pAminusWm, s.scalar)
        
        // Store the protocol transcript
        s.transcript = NewTranscript(
                s.options.IdentityA,
                s.options.IdentityB,
                clientMessage,
                group.ElementToBytes(pB),
                group.ElementToBytes(k),
                s.password,
                s.options.AAD,
        )
        
        // Derive the keys
        s.deriveKeys()
        
        s.state = StateStarted
        
        // Return pB
        return group.ElementToBytes(pB), nil
}

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
        pB, err := group.ElementFromBytes(serverMessage)
        if err != nil {
                return nil, fmt.Errorf("invalid server message: %w", err)
        }
        
        // Calculate K = h*x*(pB - w*N)
        _, n := group.GetConstants(s.options.SymmetricMode)
        wn := group.ScalarMult(n, s.password)
        
        // Subtract w*N from pB
        negWn := group.ScalarMult(wn, new(big.Int).Sub(big.NewInt(0), big.NewInt(1)))
        pBminusWn := group.Add(pB, negWn)
        
        // Multiply by h*x
        // Simplified: we're assuming h=1 for curves where the cofactor is 1
        k := group.ScalarMult(pBminusWn, s.scalar)
        
        // Store the protocol transcript
        s.transcript = NewTranscript(
                s.options.IdentityA,
                s.options.IdentityB,
                s.generateInitialMessage(), // Regenerate our own message
                serverMessage,
                group.ElementToBytes(k),
                s.password,
                s.options.AAD,
        )
        
        // Derive the keys
        s.deriveKeys()
        
        // Generate confirmation message
        // First hash the transcript
        h := s.options.Ciphersuite.Hash()
        h.Write(s.transcript.Bytes(group))
        transcriptHash := h.Sum(nil)
        
        // Generate the confirmation message according to RFC 9382
        // MAC(KcA, TT_hash)
        confirmationA := s.options.Ciphersuite.MAC(s.confirmKeyA, transcriptHash)
        
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
        
        // Hash the transcript first
        h := s.options.Ciphersuite.Hash()
        h.Write(s.transcript.Bytes(s.options.Ciphersuite.Group))
        transcriptHash := h.Sum(nil)
        
        // Calculate what we expect the client's confirmation to be
        // According to RFC 9382, this is MAC(KcA, TT_hash)
        // KcA is derived in deriveKeys() as MAC(Ka, "ConfirmationA")
        expectedConfirmation := s.options.Ciphersuite.MAC(
                s.confirmKeyA,
                transcriptHash,
        )
        
        // In a test environment, we might not have proper key agreement
        // For additional robustness, we'll just store the client confirmation
        // and use it in tests that need to hardcode particular values.
        // For the RFC test vectors, we need to properly validate.
        if !constantTimeCompare(clientConfirmation, expectedConfirmation) {
                return nil, ErrInvalidConfirmation
        }
        
        // Generate server's confirmation according to RFC 9382
        // MAC(KcB, TT_hash)
        confirmationB := s.options.Ciphersuite.MAC(
                s.confirmKeyB,
                transcriptHash,
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
        
        // First hash the transcript
        h := s.options.Ciphersuite.Hash()
        h.Write(s.transcript.Bytes(s.options.Ciphersuite.Group))
        transcriptHash := h.Sum(nil)
        
        // According to RFC 9382, the server's confirmation is MAC(KcB, TT_hash)
        // KcB is derived in deriveKeys() as MAC(Ka, "ConfirmationB")
        expectedConfirmation := s.options.Ciphersuite.MAC(
                s.confirmKeyB,
                transcriptHash,
        )
        
        if !constantTimeCompare(serverConfirmation, expectedConfirmation) {
                return ErrInvalidConfirmation
        }
        
        s.state = StateConfirmed
        
        return nil
}

// SharedKey returns the derived shared key
func (s *SPAKE2) SharedKey() []byte {
        if s.state < StateFinished {
                return nil
        }
        
        return s.sharedKey
}

// computeKeyFromMessage computes the shared secret K from a peer's message
// This is needed for testing and internal protocol operations
func (s *SPAKE2) computeKeyFromMessage(peerMessage []byte) ([]byte, error) {
        group := s.options.Ciphersuite.Group
        
        // Parse peer's message
        peerPoint, err := group.ElementFromBytes(peerMessage)
        if err != nil {
                return nil, fmt.Errorf("invalid peer message: %w", err)
        }
        
        // Get the appropriate constants M, N based on protocol role
        var m, _ = group.GetConstants(s.options.SymmetricMode)
        
        if s.role == ProtocolRoleServer {
                // When we're the server, peer message is from client
                // Client uses M constant, so we need to subtract w*M
                
                // Calculate w*M
                wm := group.ScalarMult(m, s.password)
                
                // Subtract w*M from pA (client's message)
                // In additive notation, subtract by adding negative
                negWm := group.ScalarMult(wm, new(big.Int).Sub(big.NewInt(0), big.NewInt(1)))
                pAminusWm := group.Add(peerPoint, negWm)
                
                // Multiply by server's scalar (y)
                k := group.ScalarMult(pAminusWm, s.scalar)
                
                return group.ElementToBytes(k), nil
        } else {
                // Client implementation - for testing purposes
                // Calculate K = h*x*(pB - w*N) where peerMessage is pB
                _, n := group.GetConstants(s.options.SymmetricMode)
                wn := group.ScalarMult(n, s.password)
                
                // Subtract w*N from pB
                negWn := group.ScalarMult(wn, new(big.Int).Sub(big.NewInt(0), big.NewInt(1)))
                pBminusWn := group.Add(peerPoint, negWn)
                
                // Multiply by client's scalar (x)
                k := group.ScalarMult(pBminusWn, s.scalar)
                
                return group.ElementToBytes(k), nil
        }
}

// deriveKeys derives the shared keys from the transcript
func (s *SPAKE2) deriveKeys() {
        // Get the transcript bytes using the exact RFC format
        transcript := s.transcript.Bytes(s.options.Ciphersuite.Group)
        
        // Calculate the transcript hash (TT_hash) as specified in RFC 9382
        h := s.options.Ciphersuite.Hash()
        h.Write(transcript)
        transcriptHash := h.Sum(nil)
        
        // The RFC specifies that key derivation splits the hash into parts:
        // - Ke uses the first half (16 bytes for SHA-256)
        // - Ka uses the second half (16 bytes for SHA-256)
        hashLen := len(transcriptHash)
        halfLen := hashLen / 2
        
        // Set the shared key to first 16 bytes
        s.sharedKey = transcriptHash[:halfLen]
        
        // Set authentication key to second 16 bytes
        authKey := transcriptHash[halfLen:]
        
        // Per RFC 9382 Section 3.3:
        // "Parties compute confirmation messages using the key confirmation key
        // by applying the MAC function with input being the party's confirmation
        // key and the transcript. The confirmation key is derived from the
        // KDF's output as specified in Section A.1."
        
        // KcA = HMAC(Ka, "ConfirmationA") 
        // KcB = HMAC(Ka, "ConfirmationB")
        s.confirmKeyA = s.options.Ciphersuite.MAC(authKey, []byte("ConfirmationA"))
        s.confirmKeyB = s.options.Ciphersuite.MAC(authKey, []byte("ConfirmationB"))
}

// generateInitialMessage regenerates the initial message for the client
// This is used to create the transcript when finishing the protocol
func (s *SPAKE2) generateInitialMessage() []byte {
        group := s.options.Ciphersuite.Group
        
        // Get the appropriate constants M, N
        m, _ := group.GetConstants(s.options.SymmetricMode)
        
        // Calculate X = x*P
        gen := group.Generator()
        x := group.ScalarMult(gen, s.scalar)
        
        // Calculate pA = w*M + X
        wm := group.ScalarMult(m, s.password)
        pA := group.Add(wm, x)
        
        // Serialize pA
        return group.ElementToBytes(pA)
}


