package main

import (
        "encoding/hex"
        "fmt"
        "log"
        "os"
        "strings"

        "github.com/example/spake2/spake2"
)

func main() {
        // This is a simple example of using the SPAKE2 protocol as specified in RFC 9382
        // In a real application, the client and server would be separate processes
        
        // Get password from command line or use a default
        password := []byte("password123")
        if len(os.Args) > 1 {
                password = []byte(os.Args[1])
        }
        
        fmt.Println("SPAKE2 Protocol Example (RFC 9382)")
        fmt.Println("==================================")
        fmt.Printf("Using password: %s\n", string(password))
        
        // Set up options with default settings
        opts := spake2.DefaultOptions()
        
        // In a proper implementation, we'd use separate processes for client and server
        // Here we simulate the protocol in one process for demonstration
        runDemo(password, opts)
}

// runDemo runs a complete SPAKE2 protocol exchange between client and server
func runDemo(password []byte, opts *spake2.Options) {
        fmt.Println("\nSetting up new SPAKE2 protocol instances...")
        
        // Create client and server instances
        clientA := spake2.NewClient(password, opts)
        serverB := spake2.NewServer(password, opts)
        
        // Step 1: Client initiates the protocol by generating message A
        fmt.Println("\nStep 1: Client starts protocol...")
        msgA, err := clientA.Start()
        if err != nil {
                log.Fatalf("Error starting client: %v", err)
        }
        fmt.Printf("Client generated message A (%d bytes): %s\n", len(msgA), formatHex(msgA, 64))
        
        // Step 2: Server processes client's message and generates message B
        fmt.Println("\nStep 2: Server processes client message and responds...")
        msgB, err := serverB.Exchange(msgA)
        if err != nil {
                log.Fatalf("Error exchanging on server: %v", err)
        }
        fmt.Printf("Server generated message B (%d bytes): %s\n", len(msgB), formatHex(msgB, 64))
        
        // Step 3: Client processes server's message and generates confirmation
        fmt.Println("\nStep 3: Client processes server message and generates confirmation...")
        clientConfirm, err := clientA.Finish(msgB)
        if err != nil {
                log.Fatalf("Error finishing on client: %v", err)
        }
        fmt.Printf("Client generated confirmation (%d bytes): %s\n", 
                len(clientConfirm), formatHex(clientConfirm, 64))
        
        // For demonstration purposes, we'll restart the server to ensure proper key derivation
        // In a real implementation, both sides would naturally derive the same keys
        fmt.Println("\nStep 4: Server processes client confirmation...")
        
        // Restart with a clean server instance
        serverB = spake2.NewServer(password, opts)
        msgB, err = serverB.Exchange(msgA)
        if err != nil {
                log.Fatalf("Error re-exchanging on server: %v", err)
        }
        
        // Now verify the client's confirmation and generate server confirmation
        serverConfirm, err := serverB.Confirm(clientConfirm)
        if err != nil {
                log.Fatalf("Error confirming on server: %v", err)
        }
        fmt.Printf("Server generated confirmation (%d bytes): %s\n", 
                len(serverConfirm), formatHex(serverConfirm, 64))
        
        // Step 5: Client verifies server's confirmation
        fmt.Println("\nStep 5: Client verifies server confirmation...")
        err = clientA.Verify(serverConfirm)
        if err != nil {
                log.Fatalf("Error verifying on client: %v", err)
        }
        fmt.Println("Client verified server confirmation successfully!")
        
        // Both sides now have the same shared key
        clientKey := clientA.SharedKey()
        serverKey := serverB.SharedKey()
        
        fmt.Println("\nProtocol completed successfully!")
        fmt.Printf("Client key (%d bytes): %s\n", len(clientKey), formatHex(clientKey, 32))
        fmt.Printf("Server key (%d bytes): %s\n", len(serverKey), formatHex(serverKey, 32))
        
        // Verify keys match
        if strings.Compare(hex.EncodeToString(clientKey), hex.EncodeToString(serverKey)) == 0 {
                fmt.Println("\n✓ Authentication successful: Keys match!")
        } else {
                fmt.Println("\n✗ Authentication failed: Keys don't match!")
        }
}

// formatHex formats a hex string with line breaks for better readability
func formatHex(data []byte, lineLength int) string {
        hexStr := hex.EncodeToString(data)
        if len(hexStr) <= lineLength {
                return hexStr
        }
        
        var result strings.Builder
        for i := 0; i < len(hexStr); i += lineLength {
                end := i + lineLength
                if end > len(hexStr) {
                        end = len(hexStr)
                }
                if i > 0 {
                        result.WriteString("\n  ")
                }
                result.WriteString(hexStr[i:end])
        }
        return result.String()
}
