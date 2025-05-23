package spake2

import (
        "crypto/elliptic"
        "crypto/sha256"
        "encoding/hex"
        "fmt"
        "math/big"
)

// Group represents an abstract group used in the SPAKE2 protocol
type Group interface {
        // Name returns the name of the group
        Name() string

        // ElementLength returns the length of a serialized group element in bytes
        ElementLength() int

        // ScalarLength returns the length of a serialized scalar in bytes
        ScalarLength() int

        // Order returns the order of the prime subgroup
        Order() *big.Int

        // Generator returns the generator point
        Generator() Element

        // RandomScalar generates a random scalar suitable for this group
        RandomScalar() (*big.Int, error)

        // ElementFromBytes deserializes a group element
        ElementFromBytes(data []byte) (Element, error)

        // ElementToBytes serializes a group element
        ElementToBytes(element Element) []byte

        // ScalarMult multiplies an element by a scalar
        ScalarMult(element Element, scalar *big.Int) Element

        // Add adds two elements
        Add(a, b Element) Element

        // Equal checks if two elements are equal
        Equal(a, b Element) bool

        // Identity returns the identity element of the group
        Identity() Element

        // GetConstants returns the M and N constants for the group
        GetConstants(symmetric bool) (m, n Element)
}

// Element represents a generic group element
type Element interface{}

// ECGroup implements the Group interface for elliptic curve groups
type ECGroup struct {
        curve elliptic.Curve
        m, n  Element // Constants M and N
}

// ECPoint represents a point on an elliptic curve
type ECPoint struct {
        X, Y *big.Int
}

// P256Group returns a group for the P-256 elliptic curve
func P256Group() Group {
        curve := elliptic.P256()
        m := generateMforCurve(curve)
        n := generateNforCurve(curve)
        return &ECGroup{
                curve: curve,
                m:     m,
                n:     n,
        }
}

// generateMforCurve generates the M point for a given curve
// These values should match the ones specified in the RFC
func generateMforCurve(curve elliptic.Curve) *ECPoint {
        // For P-256, the RFC specifies these coordinates for M
        if curve == elliptic.P256() {
                // RFC 9382 Appendix B specifies M in compressed format
                mCompressed, _ := hex.DecodeString("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
                x, y := elliptic.UnmarshalCompressed(curve, mCompressed)
                if x == nil || y == nil {
                        // Fallback to manual coordinate specification if needed
                        x, _ = new(big.Int).SetString("886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f", 16)
                        y, _ = curve.ScalarBaseMult(x.Bytes()) // Compute y coordinate
                }
                return &ECPoint{X: x, Y: y}
        }
        
        // For other curves, implement the generation method described in RFC 9380
        // This is a simplified approach; a production implementation should follow RFC 9380 exactly
        h := sha256.New()
        h.Write([]byte("M SPAKE2 seed OID " + curve.Params().Name))
        seed := h.Sum(nil)
        
        x, y := elliptic.UnmarshalCompressed(curve, append([]byte{0x02}, seed...))
        return &ECPoint{X: x, Y: y}
}

// generateNforCurve generates the N point for a given curve
// These values should match the ones specified in the RFC
func generateNforCurve(curve elliptic.Curve) *ECPoint {
        // For P-256, the RFC specifies these coordinates for N
        if curve == elliptic.P256() {
                // RFC 9382 Appendix B specifies N in compressed format
                nCompressed, _ := hex.DecodeString("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
                x, y := elliptic.UnmarshalCompressed(curve, nCompressed)
                if x == nil || y == nil {
                        // Fallback to manual coordinate specification if needed
                        x, _ = new(big.Int).SetString("d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49", 16)
                        y, _ = curve.ScalarBaseMult(x.Bytes()) // Compute y coordinate
                }
                return &ECPoint{X: x, Y: y}
        }
        
        // For other curves, implement the generation method described in RFC 9380
        // This is a simplified approach; a production implementation should follow RFC 9380 exactly
        h := sha256.New()
        h.Write([]byte("N SPAKE2 seed OID " + curve.Params().Name))
        seed := h.Sum(nil)
        
        x, y := elliptic.UnmarshalCompressed(curve, append([]byte{0x02}, seed...))
        return &ECPoint{X: x, Y: y}
}

// Name returns the name of the group
func (g *ECGroup) Name() string {
        return g.curve.Params().Name
}

// ElementLength returns the length of a serialized group element in bytes
func (g *ECGroup) ElementLength() int {
        return (g.curve.Params().BitSize + 7) / 8 * 2 + 1 // Uncompressed format
}

// ScalarLength returns the length of a serialized scalar in bytes
func (g *ECGroup) ScalarLength() int {
        return (g.curve.Params().BitSize + 7) / 8
}

// Order returns the order of the prime subgroup
func (g *ECGroup) Order() *big.Int {
        return g.curve.Params().N
}

// Generator returns the generator point
func (g *ECGroup) Generator() Element {
        return &ECPoint{
                X: g.curve.Params().Gx,
                Y: g.curve.Params().Gy,
        }
}

// RandomScalar generates a random scalar suitable for this group
func (g *ECGroup) RandomScalar() (*big.Int, error) {
        order := g.curve.Params().N
        k, err := randomInt(order)
        if err != nil {
                return nil, err
        }
        return k, nil
}

// ElementFromBytes deserializes a group element
func (g *ECGroup) ElementFromBytes(data []byte) (Element, error) {
        if len(data) == 0 {
                return nil, fmt.Errorf("empty data")
        }
        
        // Check if it's in uncompressed format
        if data[0] == 0x04 && len(data) == g.ElementLength() {
                x, y := elliptic.Unmarshal(g.curve, data)
                if x == nil || y == nil {
                        return nil, fmt.Errorf("invalid point encoding")
                }
                return &ECPoint{X: x, Y: y}, nil
        }
        
        // Check if it's in compressed format
        if (data[0] == 0x02 || data[0] == 0x03) && len(data) == g.ScalarLength()+1 {
                x, y := elliptic.UnmarshalCompressed(g.curve, data)
                if x == nil || y == nil {
                        return nil, fmt.Errorf("invalid compressed point encoding")
                }
                return &ECPoint{X: x, Y: y}, nil
        }
        
        return nil, fmt.Errorf("invalid point format")
}

// ElementToBytes serializes a group element
func (g *ECGroup) ElementToBytes(element Element) []byte {
        point, ok := element.(*ECPoint)
        if !ok {
                return nil
        }
        return elliptic.Marshal(g.curve, point.X, point.Y)
}

// ScalarMult multiplies an element by a scalar
func (g *ECGroup) ScalarMult(element Element, scalar *big.Int) Element {
        point, ok := element.(*ECPoint)
        if !ok {
                return nil
        }
        x, y := g.curve.ScalarMult(point.X, point.Y, scalar.Bytes())
        return &ECPoint{X: x, Y: y}
}

// Add adds two elements
func (g *ECGroup) Add(a, b Element) Element {
        pointA, ok := a.(*ECPoint)
        if !ok {
                return nil
        }
        pointB, ok := b.(*ECPoint)
        if !ok {
                return nil
        }
        x, y := g.curve.Add(pointA.X, pointA.Y, pointB.X, pointB.Y)
        return &ECPoint{X: x, Y: y}
}

// Equal checks if two elements are equal
func (g *ECGroup) Equal(a, b Element) bool {
        pointA, ok := a.(*ECPoint)
        if !ok {
                return false
        }
        pointB, ok := b.(*ECPoint)
        if !ok {
                return false
        }
        return pointA.X.Cmp(pointB.X) == 0 && pointA.Y.Cmp(pointB.Y) == 0
}

// Identity returns the identity element of the group
func (g *ECGroup) Identity() Element {
        // Point at infinity
        return &ECPoint{X: nil, Y: nil}
}

// GetConstants returns the M and N constants for the group
func (g *ECGroup) GetConstants(symmetric bool) (m, n Element) {
        if symmetric {
                return g.m, g.m
        }
        return g.m, g.n
}
