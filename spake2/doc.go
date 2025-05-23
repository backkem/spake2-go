// Package spake2 implements the SPAKE2 password-authenticated key exchange
// protocol as defined in RFC 9382.
//
// SPAKE2 enables two parties that share a password to derive a strong shared key
// without disclosing the password. This implementation follows the RFC 9382 
// specification and provides support for various elliptic curve groups.
//
// Basic usage:
//
//	// Initialize the protocol with a shared password
//	password := []byte("password123")
//	opts := spake2.DefaultOptions()
//	
//	// Create client and server instances
//	client := spake2.NewClient(password, opts)
//	server := spake2.NewServer(password, opts)
//	
//	// Generate the first message from client (A)
//	msgA, err := client.Start()
//	if err != nil {
//	    // handle error
//	}
//	
//	// Process client's message and generate response from server (B)
//	msgB, err := server.Exchange(msgA)
//	if err != nil {
//	    // handle error
//	}
//	
//	// Complete the exchange on client side
//	clientConfirm, err := client.Finish(msgB)
//	if err != nil {
//	    // handle error
//	}
//	
//	// Complete the exchange on server side
//	serverConfirm, err := server.Confirm(clientConfirm)
//	if err != nil {
//	    // handle error
//	}
//	
//	// Send server confirmation to client
//	err = client.Verify(serverConfirm)
//	if err != nil {
//	    // handle error
//	}
//	
//	// Both sides now have the same shared key
//	clientKey := client.SharedKey()
//	serverKey := server.SharedKey()
//
// The implementation supports different elliptic curve groups and can be
// configured with custom parameters if needed.
package spake2
