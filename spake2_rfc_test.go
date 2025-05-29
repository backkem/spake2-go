package spake2

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/backkem/spake2/internal/crypto"
	"go.dedis.ch/kyber/v4"
)

// stripHexPrefix removes the "0x" prefix from a hex string if present
func stripHexPrefix(hexStr string) string {
	if len(hexStr) > 2 && hexStr[:2] == "0x" {
		return hexStr[2:]
	}
	return hexStr
}

func mustParseHex(hexStr string) []byte {
	hexStr = stripHexPrefix(hexStr)
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse hex string: %v", err))
	}
	return b
}

// parseHexScalar parses a hex string into a Scalar, handling optional "0x" prefix
func parseHexScalar(c crypto.Group, hexStr string) (kyber.Scalar, error) {
	hexStr = stripHexPrefix(hexStr)
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	return c.Scalar().SetBytes(b), nil
}

func mustParseHexScalar(c crypto.Group, hexStr string) kyber.Scalar {
	s, err := parseHexScalar(c, hexStr)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse hex scalar: %v", err))
	}
	return s
}

func TestParseHexScalar(t *testing.T) {
	sHex := "0x2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f"
	w, err := parseHexScalar(crypto.P256Group(), sHex)
	if err != nil {
		t.Fatalf("Failed to parse hex scalar: %v", err)
	}
	wData, err := w.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal scalar: %v", err)
	}
	actual := "0x" + hex.EncodeToString(wData)
	if actual != sHex {
		t.Fatalf("Failed to parse hex scalar: expected %s, got %s", sHex, actual)
	}
}

// parseHexPoint parses a hex string into a big.Int, handling optional "0x" prefix
func parseHexPoint(c crypto.Group, hexStr string) (kyber.Point, error) {
	hexStr = stripHexPrefix(hexStr)
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	// Handle uncompressed point format (0x04 prefix)
	if b[0] == 0x04 && len(b) == c.PointLen() {
		//lint:ignore SA1019 deprecated function used for compatibility
		x, y := elliptic.Unmarshal(c.Curve(), b)
		if x == nil || y == nil {
			return nil, fmt.Errorf("invalid uncompressed point encoding")
		}
		return crypto.NewPoint(c, x, y)
	}

	// Handle compressed point format (0x02 or 0x03 prefix)
	if (b[0] == 0x02 || b[0] == 0x03) && len(b) == c.ScalarLen()+1 {
		x, y := elliptic.UnmarshalCompressed(c.Curve(), b)
		if x == nil || y == nil {
			return nil, fmt.Errorf("invalid compressed point encoding")
		}
		return crypto.NewPoint(c, x, y)
	}

	// Return error for unsupported formats
	return nil, fmt.Errorf("invalid point format: unrecognized prefix or length")
}
func mustParseHexPoint(c crypto.Group, hexStr string) kyber.Point {
	p, err := parseHexPoint(c, hexStr)
	if err != nil {
		panic(err)
	}
	return p
}

func TestParseHexPoint(t *testing.T) {
	pHex := "0x04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c"
	w, err := parseHexPoint(crypto.P256Group(), pHex)
	if err != nil {
		t.Fatalf("Failed to parse hex scalar: %v", err)
	}
	wData, err := w.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal scalar: %v", err)
	}
	actual := "0x" + hex.EncodeToString(wData)
	if actual != pHex {
		t.Fatalf("Failed to parse hex scalar: expected %s, got %s", pHex, actual)
	}
}

type RFCVectorData struct {
	name   string
	idA    string // A's identity
	idB    string // B's identity
	m      kyber.Point
	n      kyber.Point  // N point for the curve (compressed hex)
	w      kyber.Scalar // w as hex string (password hash)
	x      kyber.Scalar // x as hex string (A's random scalar)
	y      kyber.Scalar // y as hex string (B's random scalar)
	pA     kyber.Point  // pA = w*M + X (uncompressed hex)
	pB     kyber.Point  // pB = w*N + Y (uncompressed hex)
	k      kyber.Point  // K = shared point (uncompressed hex)
	tt     []byte       // Transcript hash input (hex)
	hashTT []byte       // Hash(TT) (hex)
	ke     []byte       // Ke = encryption key (hex)
	ka     []byte       // Ka = authentication key (hex)
	kcA    []byte       // KcA = confirmation key for A (hex)
	kcB    []byte       // KcB = confirmation key for B (hex)
	aConf  []byte       // A's confirmation message (hex)
	bConf  []byte       // B's confirmation message (hex)
}

// TestRFCVectors tests the SPAKE2 implementation against the test vectors
// provided in RFC 9382 Appendix B.
func TestRFCVectors(t *testing.T) {
	// Table based test matching the RFC test vectors exactly
	tests := []struct {
		name      string
		idA       string // A's identity
		idB       string // B's identity
		mHex      string // M point for the curve (compressed hex)
		nHex      string // N point for the curve (compressed hex)
		wHex      string // w as hex string (password hash)
		xHex      string // x as hex string (A's random scalar)
		yHex      string // y as hex string (B's random scalar)
		pAHex     string // pA = w*M + X (uncompressed hex)
		pBHex     string // pB = w*N + Y (uncompressed hex)
		kHex      string // K = shared point (uncompressed hex)
		ttHex     string // Transcript hash input (hex)
		hashTTHex string // Hash(TT) (hex)
		keHex     string // Ke = encryption key (hex)
		kaHex     string // Ka = authentication key (hex)
		kcAHex    string // KcA = confirmation key for A (hex)
		kcBHex    string // KcB = confirmation key for B (hex)
		aConfHex  string // A's confirmation message (hex)
		bConfHex  string // B's confirmation message (hex)
	}{
		{
			name:      "P-256 Test Vector 1 from RFC 9382",
			idA:       "server",
			idB:       "client",
			mHex:      P256_M_HEX,
			nHex:      P256_N_HEX,
			wHex:      "0x2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f",
			xHex:      "0x43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729",
			yHex:      "0xdcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be",
			pAHex:     "0x04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c",
			pBHex:     "0x0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7",
			kHex:      "0x0412af7e89717850671913e6b469ace67bd90a4df8ce45c2af19010175e37eed69f75897996d539356e2fa6a406d528501f907e04d97515fbe83db277b715d3325",
			ttHex:     "0x06000000000000007365727665720600000000000000636c69656e74410000000000000004a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c41000000000000000406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b741000000000000000412af7e89717850671913e6b469ace67bd90a4df8ce45c2af19010175e37eed69f75897996d539356e2fa6a406d528501f907e04d97515fbe83db277b715d332520000000000000002ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f",
			hashTTHex: "0x0e0672dc86f8e45565d338b0540abe6915bdf72e2b35b5c9e5663168e960a91b",
			keHex:     "0x0e0672dc86f8e45565d338b0540abe69",
			kaHex:     "0x15bdf72e2b35b5c9e5663168e960a91b",
			kcAHex:    "0x00c12546835755c86d8c0db7851ae86f",
			kcBHex:    "0xa9fa3406c3b781b93d804485430ca27a",
			aConfHex:  "0x58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0",
			bConfHex:  "0xd3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b",
		},
		{
			name:      "P-256 Test Vector 2 from RFC 9382",
			idA:       "",
			idB:       "client",
			mHex:      P256_M_HEX,
			nHex:      P256_N_HEX,
			wHex:      "0x0548d8729f730589e579b0475a582c1608138ddf7054b73b5381c7e883e2efae",
			xHex:      "0x403abbe3b1b4b9ba17e3032849759d723939a27a27b9d921c500edde18ed654b",
			yHex:      "0x903023b6598908936ea7c929bd761af6039577a9c3f9581064187c3049d87065",
			pAHex:     "0x04a897b769e681c62ac1c2357319a3d363f610839c4477720d24cbe32f5fd85f44fb92ba966578c1b712be6962498834078262caa5b441ecfa9d4a9485720e918a",
			pBHex:     "0x04e0f816fd1c35e22065d5556215c097e799390d16661c386e0ecc84593974a61b881a8c82327687d0501862970c64565560cb5671f696048050ca66ca5f8cc7fc",
			kHex:      "0x048f83ec9f6e4f87cc6f9dc740bdc2769725f923364f01c84148c049a39a735ebda82eac03e00112fd6a5710682767cff5361f7e819e53d8d3c3a2922e0d837aa6",
			ttHex:     "0x00000000000000000600000000000000636c69656e74410000000000000004a897b769e681c62ac1c2357319a3d363f610839c4477720d24cbe32f5fd85f44fb92ba966578c1b712be6962498834078262caa5b441ecfa9d4a9485720e918a410000000000000004e0f816fd1c35e22065d5556215c097e799390d16661c386e0ecc84593974a61b881a8c82327687d0501862970c64565560cb5671f696048050ca66ca5f8cc7fc4100000000000000048f83ec9f6e4f87cc6f9dc740bdc2769725f923364f01c84148c049a39a735ebda82eac03e00112fd6a5710682767cff5361f7e819e53d8d3c3a2922e0d837aa620000000000000000548d8729f730589e579b0475a582c1608138ddf7054b73b5381c7e883e2efae",
			hashTTHex: "0x642f05c473c2cd79909f9a841e2f30a70bf89b18180af97353ba198789c2b963",
			keHex:     "0x642f05c473c2cd79909f9a841e2f30a7",
			kaHex:     "0x0bf89b18180af97353ba198789c2b963",
			kcAHex:    "0xc6be376fc7cd1301fd0a13adf3e7bffd",
			kcBHex:    "0xb7243f4ae60440a49b3f8cab3c1fba07",
			aConfHex:  "0x47d29e6666af1b7dd450d571233085d7a9866e4d49d2645e2df975489521232b",
			bConfHex:  "0x3313c5cefc361d27fb16847a91c2a73b766ffa90a4839122a9b70a2f6bd1d6df",
		},
		{
			name:      "P-256 Test Vector 3 from RFC 9382",
			idA:       "server",
			idB:       "",
			mHex:      P256_M_HEX,
			nHex:      P256_N_HEX,
			wHex:      "0x626e0cdc7b14c9db3e52a0b1b3a768c98e37852d5db30febe0497b14eae8c254",
			xHex:      "0x07adb3db6bc623d3399726bfdbfd3d15a58ea776ab8a308b00392621291f9633",
			yHex:      "0xb6a4fc8dbb629d4ba51d6f91ed1532cf87adec98f25dd153a75accafafedec16",
			pAHex:     "0x04f88fb71c99bfffaea370966b7eb99cd4be0ff1a7d335caac4211c4afd855e2e15a873b298503ad8ba1d9cbb9a392d2ba309b48bfd7879aefd0f2cea6009763b0",
			pBHex:     "0x040c269d6be017dccb15182ac6bfcd9e2a14de019dd587eaf4bdfd353f031101e7cca177f8eb362a6e83e7d5e729c0732e1b528879c086f39ba0f31a9661bd34db",
			kHex:      "0x0445ee233b8ecb51ebd6e7da3f307e88a1616bae2166121221fdc0dadb986afaf3ec8a988dc9c626fa3b99f58a7ca7c9b844bb3e8dd9554aafc5b53813504c1cbe",
			ttHex:     "0x06000000000000007365727665720000000000000000410000000000000004f88fb71c99bfffaea370966b7eb99cd4be0ff1a7d335caac4211c4afd855e2e15a873b298503ad8ba1d9cbb9a392d2ba309b48bfd7879aefd0f2cea6009763b04100000000000000040c269d6be017dccb15182ac6bfcd9e2a14de019dd587eaf4bdfd353f031101e7cca177f8eb362a6e83e7d5e729c0732e1b528879c086f39ba0f31a9661bd34db41000000000000000445ee233b8ecb51ebd6e7da3f307e88a1616bae2166121221fdc0dadb986afaf3ec8a988dc9c626fa3b99f58a7ca7c9b844bb3e8dd9554aafc5b53813504c1cbe2000000000000000626e0cdc7b14c9db3e52a0b1b3a768c98e37852d5db30febe0497b14eae8c254",
			hashTTHex: "0x005184ff460da2ce59062c87733c299c3521297d736598fc0a1127600efa1afb",
			keHex:     "0x005184ff460da2ce59062c87733c299c",
			kaHex:     "0x3521297d736598fc0a1127600efa1afb",
			kcAHex:    "0xf3da53604f0aeecea5a33be7bddf6edf",
			kcBHex:    "0x9e3f86848736f159bd92b6e107ec6799",
			aConfHex:  "0xbc9f9bbe99f26d0b2260e6456e05a86196a3307ec6663a18bf6ac825736533b2",
			bConfHex:  "0xc2370e1bf813b086dff0d834e74425a06e6390f48f5411900276dcccc5a297ec",
		},
		{
			name:      "P-256 Test Vector 4 from RFC 9382",
			idA:       "",
			idB:       "",
			mHex:      P256_M_HEX,
			nHex:      P256_N_HEX,
			wHex:      "0x7bf46c454b4c1b25799527d896508afd5fc62ef4ec59db1efb49113063d70cca",
			xHex:      "0x8cef65df64bb2d0f83540c53632de911b5b24b3eab6cc74a97609fd659e95473",
			yHex:      "0xd7a66f64074a84652d8d623a92e20c9675c61cb5b4f6a0063e4648a2fdc02d53",
			pAHex:     "0x04a65b367a3f613cf9f0654b1b28a1e3a8a40387956c8ba6063e8658563890f46ca1ef6a676598889fc28de2950ab8120b79a5ef1ea4c9f44bc98f585634b46d66",
			pBHex:     "0x04589f13218822710d98d8b2123a079041052d9941b9cf88c6617ddb2fcc0494662eea8ba6b64692dc318250030c6af045cb738bc81ba35b043c3dcb46adf6f58d",
			kHex:      "0x041a3c03d51b452537ca2a1fea6110353c6d5ed483c4f0f86f4492ca3f378d40a994b4477f93c64d928edbbcd3e85a7c709b7ea73ee97986ce3d1438e135543772",
			ttHex:     "0x00000000000000000000000000000000410000000000000004a65b367a3f613cf9f0654b1b28a1e3a8a40387956c8ba6063e8658563890f46ca1ef6a676598889fc28de2950ab8120b79a5ef1ea4c9f44bc98f585634b46d66410000000000000004589f13218822710d98d8b2123a079041052d9941b9cf88c6617ddb2fcc0494662eea8ba6b64692dc318250030c6af045cb738bc81ba35b043c3dcb46adf6f58d4100000000000000041a3c03d51b452537ca2a1fea6110353c6d5ed483c4f0f86f4492ca3f378d40a994b4477f93c64d928edbbcd3e85a7c709b7ea73ee97986ce3d1438e13554377220000000000000007bf46c454b4c1b25799527d896508afd5fc62ef4ec59db1efb49113063d70cca",
			hashTTHex: "0xfc6374762ba5cf11f4b2caa08b2cd1b9907ae0e26e8d6234318d91583cd74c86",
			keHex:     "0xfc6374762ba5cf11f4b2caa08b2cd1b9",
			kaHex:     "0x907ae0e26e8d6234318d91583cd74c86",
			kcAHex:    "0x5dbd2f477166b7fb6d61febbd77a5563",
			kcBHex:    "0x7689b4654407a5faeffdc8f18359d8a3",
			aConfHex:  "0xdfb4db8d48ae5a675963ea5e6c19d98d4ea028d8e898dad96ea19a80ade95dca",
			bConfHex:  "0xd0f0609d1613138d354f7e95f19fb556bf52d751947241e8c7118df5ef0ae175",
		},
	}

	suite := DefaultCiphersuite()
	group := suite.Group

	testsData := []RFCVectorData{}
	for _, tt := range tests {
		ttData := RFCVectorData{
			name:   tt.name,
			idA:    tt.idA,
			idB:    tt.idB,
			m:      mustParseHexPoint(group, tt.mHex),
			n:      mustParseHexPoint(group, tt.nHex),
			w:      mustParseHexScalar(group, tt.wHex),
			x:      mustParseHexScalar(group, tt.xHex),
			y:      mustParseHexScalar(group, tt.yHex),
			pA:     mustParseHexPoint(group, tt.pAHex),
			pB:     mustParseHexPoint(group, tt.pBHex),
			k:      mustParseHexPoint(group, tt.kHex),
			tt:     mustParseHex(tt.ttHex),
			hashTT: mustParseHex(tt.hashTTHex),
			ke:     mustParseHex(tt.keHex),
			ka:     mustParseHex(tt.kaHex),
			kcA:    mustParseHex(tt.kcAHex),
			kcB:    mustParseHex(tt.kcBHex),
			aConf:  mustParseHex(tt.aConfHex),
			bConf:  mustParseHex(tt.bConfHex),
		}
		testsData = append(testsData, ttData)
	}

	for _, tt := range testsData {
		t.Run(tt.name, func(t *testing.T) {

			clientOpts := &Options{
				Ciphersuite:   suite,
				IdentityA:     []byte(tt.idA),
				IdentityB:     []byte(tt.idB),
				SymmetricMode: false,
				dbg:           true,
			}
			client := NewClient([]byte("unused; w set directly"), clientOpts)

			// Override the client password and scalar
			client.password = tt.w
			client.scalar = tt.x

			serverOpts := &Options{
				Ciphersuite:   DefaultCiphersuite(),
				IdentityA:     []byte(tt.idA),
				IdentityB:     []byte(tt.idB),
				SymmetricMode: false,
				dbg:           true,
			}

			pA, err := client.Start()
			if err != nil {
				t.Fatalf("Failed to start client: %v", err)
			}

			expectedPABytes, err := crypto.PointToBytes(tt.pA)
			if err != nil {
				t.Fatalf("Failed to marshal pA: %v", err)
			}

			if !bytes.Equal(pA, expectedPABytes) {
				t.Fatalf("Expected pA to be %v, got %v", expectedPABytes, pA)
			}

			server := NewServer([]byte("unused; w set directly"), serverOpts)

			// Override the server password and scalar
			server.password = tt.w
			server.scalar = tt.y

			pB, err := server.Exchange(pA)
			if err != nil {
				t.Fatalf("Failed to start server: %v", err)
			}

			expectedPBBytes, err := crypto.PointToBytes(tt.pB)
			if err != nil {
				t.Fatalf("Failed to marshal pB: %v", err)
			}

			if !bytes.Equal(pB, expectedPBBytes) {
				t.Fatalf("Expected pB to be %v, got %v", expectedPBBytes, pB)
			}

			validateExchange(t, server, tt)

			cA, err := client.Finish(pB)
			if err != nil {
				t.Fatalf("Failed to finish client: %v", err)
			}

			validateExchange(t, client, tt)

			if !bytes.Equal(cA, tt.aConf) {
				t.Fatalf("Expected cA to be %v, got %v", cA, tt.aConf)
			}

			cB, err := server.Confirm(cA)
			if err != nil {
				t.Fatalf("Failed to finish server: %v", err)
			}

			if !bytes.Equal(cB, tt.bConf) {
				t.Fatalf("Expected cB to be %v, got %v", cB, tt.bConf)
			}

			err = client.Verify(cB)
			if err != nil {
				t.Fatalf("Client failed to verify: %v", err)
			}

		})

	}
}

func validateExchange(t *testing.T, actual *SPAKE2, expected RFCVectorData) {
	expectedKBytes, err := crypto.PointToBytes(expected.k)
	if err != nil {
		t.Fatalf("Failed to marshal k: %v", err)
	}
	// Validate k
	if !bytes.Equal(actual.transcript.K, expectedKBytes) {
		t.Fatalf("Expected %s k to be %v, got %v", actual.role, expectedKBytes, actual.transcript.K)
	}

	// Validate tt (transcript hash input)
	if !bytes.Equal(actual.dbgTT, expected.tt) {
		t.Fatalf("Expected %s tt to be\n%v, got\n%v", actual.role, expected.tt, actual.dbgTT)
	}

	// Validate hashTT (hash of transcript)
	if !bytes.Equal(actual.dbgHash, expected.hashTT) {
		t.Fatalf("Expected %s hashTT to be %v, got %v", actual.role, expected.hashTT, actual.dbgHash)
	}

	// Validate ke (encryption key)
	if !bytes.Equal(actual.sharedKey, expected.ke) {
		t.Fatalf("Expected %s ke to be %v, got %v", actual.role, expected.ke, actual.sharedKey)
	}

	// Validate ka (authentication key)
	if !bytes.Equal(actual.dbgAuthKey, expected.ka) {
		t.Fatalf("Expected %s ka to be %v, got %v", actual.role, expected.ka, actual.dbgAuthKey)
	}

	// Validate kcA (confirmation key for A)
	if !bytes.Equal(actual.confirmKeyA, expected.kcA) {
		t.Fatalf("Expected %s kcA to be %v, got %v", actual.role, expected.kcA, actual.confirmKeyA)
	}

	// Validate kcB (confirmation key for B)
	if !bytes.Equal(actual.confirmKeyB, expected.kcB) {
		t.Fatalf("Expected %s kcB to be %v, got %v", actual.role, expected.kcB, actual.confirmKeyB)
	}

}
