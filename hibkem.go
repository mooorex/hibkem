package HIBKEM

import (
	"crypto/rand"
	"errors"
	"github.com/cloudflare/bn256"
	"io"
	"strings"
)

// Public parameters
type Params struct {
	G  *bn256.G2
	G1 *bn256.G2
	G2 *bn256.G1
	G3 *bn256.G1
	H  []*bn256.G1

	//in this implementation, it will be set to an empty string
	// todo: using bigint
	RootID string

	// pre-computed generator, e(g_1, g_2)
	Pairing *bn256.GT
}

// Private key for an ID in a hierarchy
// If this is the master key, then A1 = nil, B is empty
type PrivateKey struct {
	A0 *bn256.G1
	A1 *bn256.G2
	B  []*bn256.G1

	//the coresponding ID
	ID string
}

// Ciphertext
type Ciphertext struct {
	B *bn256.G2
	C *bn256.G1
}

//symmetric key
type SessionKey = bn256.GT

////////////////////////////////
func IsAncestor(testing, n string) bool {
	return strings.HasPrefix(n, testing) && len(testing) != len(n)
}

// check if testing is a descendant of n
func IsDescendant(testing, n string) bool {
	return strings.HasPrefix(testing, n) && len(testing) != len(n)
}

// Setup generates the system parameters and the master secret key.
// Parameter "l" is the system-supported maximum depth.
func Setup(r io.Reader, l int) (*Params, *PrivateKey, error) {
	params, msk := &Params{}, &PrivateKey{}
	var err error

	// g
	_, params.G, err = bn256.RandomG2(r)
	if err != nil {
		return nil, nil, err
	}

	// alpha in Z_p
	alpha, err := rand.Int(r, bn256.Order)
	if err != nil {
		return nil, nil, err
	}

	// g1 = g ^ alpha
	params.G1 = new(bn256.G2).ScalarMult(params.G, alpha)

	// g2
	_, params.G2, err = bn256.RandomG1(r)
	if err != nil {
		return nil, nil, err
	}

	// g3
	_, params.G3, err = bn256.RandomG1(r)
	if err != nil {
		return nil, nil, err
	}

	// h1 ... hl
	params.H = make([]*bn256.G1, l, l)
	for i, _ := range params.H {
		_, params.H[i], err = bn256.RandomG1(r)
		if err != nil {
			return nil, nil, err
		}
	}

	params.RootID = "E"

	// the master key = g2 ^ alpha
	msk.A0 = new(bn256.G1).ScalarMult(params.G2, alpha)
	msk.ID = params.RootID

	return params, msk, nil
}

// pre-compute the generator of G_T
func (params *Params) PreComputeGT() {
	if params.Pairing == nil &&
		params.G2 != nil &&
		params.G1 != nil {
		params.Pairing = bn256.Pair(params.G2, params.G1)
	}
}

// KeyGen generates a scecret key for an ID using its ancestor's
// private key including the matster secret key.
// WARNING: Using a ill-structed ancestor will result in UNDIFINED behavior.
func KeyGen(r io.Reader, params *Params, ancestor *PrivateKey, id string) (*PrivateKey, error) {
	if !IsAncestor(ancestor.ID, id) {
		return nil, errors.New("Not Ancestor!")
	}

	//not from the master key
	isNotMSK := len(ancestor.B) != 0

	rootIDLen := len(params.RootID)
	levels := len(params.H)
	idLevel := len(id) - rootIDLen
	ancestorLevel := len(ancestor.ID) - rootIDLen
	ancestorSKLevel := 0
	if isNotMSK {
		ancestorSKLevel = levels - len(ancestor.B)
	}

	if idLevel > levels || ancestorLevel != ancestorSKLevel {
		return nil, errors.New("Wrong depth!")
	}

	// random number s in Zp
	s, err := rand.Int(r, bn256.Order)
	if err != nil {
		return nil, err
	}

	// prod_{i = 1}^{idlevel} H[i]^s * g3^s
	prod := new(bn256.G1).Set(params.G3)
	for i, ch := range []byte(id[rootIDLen:]) {
		if ch == '1' {
			prod.Add(prod, params.H[i])
		}
	}
	prod.ScalarMult(prod, s)
	if isNotMSK {
		for i, ch := range []byte(id[rootIDLen+ancestorLevel:]) {
			if ch == '1' {
				prod.Add(prod, ancestor.B[i])
			}
		}
	}

	key := &PrivateKey{}
	key.A0 = new(bn256.G1).Add(ancestor.A0, prod)
	key.A1 = new(bn256.G2).ScalarMult(params.G, s)
	if isNotMSK {
		key.A1.Add(ancestor.A1, key.A1)
	}
	key.B = make([]*bn256.G1, levels-idLevel)
	for i, item := range params.H[idLevel:] {
		key.B[i] = new(bn256.G1).ScalarMult(item, s)
		if isNotMSK {
			key.B[i].Add(ancestor.B[i+1], key.B[i])
		}
	}
	key.ID = id

	return key, nil
}

//  Encapsulate generates a symmetric key under the provided ID
func Encapsulate(r io.Reader, params *Params, id string) (*SessionKey, *Ciphertext, error) {
	if len(id) > len(params.H) {
		return nil, nil, errors.New("Wrong depth!")
	}

	// random number s in Zp
	s, err := rand.Int(r, bn256.Order)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := &Ciphertext{}
	ciphertext.B = new(bn256.G2).ScalarMult(params.G, s)
	ciphertext.C = new(bn256.G1).Set(params.G3)
	for i, ch := range []byte(id[len(params.RootID):]) {
		if ch == '1' {
			ciphertext.C.Add(ciphertext.C, params.H[i])
		}
	}
	ciphertext.C.ScalarMult(ciphertext.C, s)

	if params.Pairing == nil {
		params.Pairing = bn256.Pair(params.G2, params.G1)
	}

	return new(bn256.GT).ScalarMult(params.Pairing, s), ciphertext, nil
}

// Decapsulate recovers the sysmetric key from the provided ciphertext
func Decapsulate(key *PrivateKey, ciphertext *Ciphertext) *SessionKey {
	return new(bn256.GT).Add(bn256.Pair(key.A0, ciphertext.B),
		new(bn256.GT).Neg(bn256.Pair(ciphertext.C, key.A1)))
}
