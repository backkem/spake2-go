package crypto

import (
	"crypto/elliptic"
	"math/big"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/nist"
	"go.dedis.ch/kyber/v4/util/random"
)

type Group interface {
	String() string
	Curve() elliptic.Curve

	ScalarLen() int
	Scalar() kyber.Scalar
	RandomScalar() kyber.Scalar

	PointLen() int
	Point() kyber.Point
	Generator() (kyber.Point, error)

	Order() *big.Int
}

type p256Group struct {
	group kyber.Group
	curve elliptic.Curve
}

func (c *p256Group) String() string {
	return c.group.String()
}
func (c *p256Group) Curve() elliptic.Curve {
	return c.curve
}
func (c *p256Group) ScalarLen() int {
	return c.group.ScalarLen()
}
func (c *p256Group) Scalar() kyber.Scalar {
	return c.group.Scalar()
}
func (c *p256Group) RandomScalar() kyber.Scalar {
	return c.group.Scalar().Pick(random.New())
}

// Generator returns the generator point
func (c *p256Group) Generator() (kyber.Point, error) {
	return NewPoint(
		c,
		c.curve.Params().Gx,
		c.curve.Params().Gy,
	)

}
func (c *p256Group) PointLen() int {
	return c.group.PointLen()
}
func (c *p256Group) Point() kyber.Point {
	return c.group.Point()
}
func (c *p256Group) Order() *big.Int {
	return c.curve.Params().N
}

// P256Group returns a group for the P-256 elliptic curve
func P256Group() Group {
	return &p256Group{
		group: nist.NewBlakeSHA256P256(),
		curve: elliptic.P256(),
	}
}

func NewPoint(c Group, x, y *big.Int) (kyber.Point, error) {
	//lint:ignore SA1019 deprecated function used for compatibility
	b := elliptic.Marshal(c.Curve(), x, y)
	p := c.Point()
	err := p.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func PointToBytes(p kyber.Point) ([]byte, error) {
	b, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return b, nil
}
func PointFromBytes(group Group, b []byte) (kyber.Point, error) {
	p := group.Point()
	err := p.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return p, nil

}
