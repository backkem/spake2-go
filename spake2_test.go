package spake2

import (
	"bytes"
	"testing"
)

func TestSPAKE2Protocol(t *testing.T) {
	// Test basic protocol flow with the client and server using the same password
	password := []byte("password123")
	opts := DefaultOptions()

	client := NewClient(password, opts)
	server := NewServer(password, opts)

	// Step 1: Client starts the protocol
	msgA, err := client.Start()
	if err != nil {
		t.Fatalf("Failed to start client: %v", err)
	}

	// Step 2: Server processes client's message and responds
	msgB, err := server.Exchange(msgA)
	if err != nil {
		t.Fatalf("Failed to exchange on server: %v", err)
	}

	// Step 3: Since both parties derive K independently, we need to ensure they compute
	// the same K value and transcript hash. In a real-world scenario, they would.

	// Step 4: Client finishes by processing the server's message and generating confirmation
	clientConfirm, err := client.Finish(msgB)
	if err != nil {
		t.Fatalf("Failed to finish on client: %v", err)
	}

	// Step 6: Server validates client's confirmation and generates its own
	serverConfirm, err := server.Confirm(clientConfirm)
	if err != nil {
		t.Fatalf("Failed to confirm on server: %v", err)
	}

	// Step 7: Client verifies server's confirmation
	err = client.Verify(serverConfirm)
	if err != nil {
		t.Fatalf("Failed to verify on client: %v", err)
	}

	// Step 8: Verify that both sides have the same shared key
	clientKey, err := client.SharedKey()
	if err != nil {
		t.Fatalf("Failed to get client key: %v", err)
	}
	serverKey, err := server.SharedKey()
	if err != nil {
		t.Fatalf("Failed to get server key: %v", err)
	}

	if !bytes.Equal(clientKey, serverKey) {
		t.Fatalf("Keys don't match: client %x, server %x", clientKey, serverKey)
	}
}

func TestInvalidPassword(t *testing.T) {
	// Test with different passwords
	passwordA := []byte("password123")
	passwordB := []byte("wrongpassword")
	opts := DefaultOptions()

	client := NewClient(passwordA, opts)
	server := NewServer(passwordB, opts)

	// Client starts
	msgA, err := client.Start()
	if err != nil {
		t.Fatalf("Failed to start client: %v", err)
	}

	// Server exchanges
	msgB, err := server.Exchange(msgA)
	if err != nil {
		t.Fatalf("Failed to exchange on server: %v", err)
	}

	// Client finishes
	clientConfirm, err := client.Finish(msgB)
	if err != nil {
		t.Fatalf("Failed to finish on client: %v", err)
	}

	// Server confirms - this should fail with different passwords
	_, err = server.Confirm(clientConfirm)
	if err == nil {
		t.Fatalf("Confirmation should have failed with different passwords")
	}
}
