package HIBKEM

import (
	"crypto/sha256"
	"errors"
	"github.com/cloudflare/bn256"
	"math/big"
)

// the marshalled value size of a G1 element is numbytes*2
// the marshalled value size of a G2 element is 1+numbytes*4, the first byte is 0x01 if it the element is not infinity, 0x00 otherwise.
// the marshalled value size of a GT element is numbytes*12

const (
	numBytes = 256 / 8     //32
	nbShift  = 5           //1<<5 = 32
	G1Count  = 1 << 1      //g1： *2
	G2Count  = 1 << 2      //g2:  *4
	GTCount  = 1<<2 + 1<<3 //gt:  *12
)

//c: one of G*Count
//n: offset
func getSlice(b []byte, gcount, offset uint) []byte {
	if gcount == G2Count {
		return b[offset<<nbShift : (offset+gcount)<<nbShift+1]
	}
	return b[offset<<nbShift : (offset+gcount)<<nbShift]
}

//////////////////////////

// Marshal encodes the ct as a byte slice.
func (ct *Ciphertext) Marshal() []byte {
	count := G2Count + G1Count
	ret := make([]byte, count<<nbShift+1)

	copy(getSlice(ret, G2Count, 0), ct.B.Marshal())
	copy(getSlice(ret, G1Count, G2Count), ct.C.Marshal())

	return ret
}

// Unmarshal recovers the ct from an encoded byte slice.
func (ct *Ciphertext) Unmarshal(ret []byte) (*Ciphertext, error) {
	count := G2Count + G1Count
	if len(ret) != count<<nbShift+1 {
		return nil, errors.New("invalid parameters")
	}

	ct.B = new(bn256.G2)
	_, err := ct.B.Unmarshal(getSlice(ret, G2Count, 0))
	if err != nil {
		return nil, err
	}
	ct.C = new(bn256.G1)
	_, err = ct.C.Unmarshal(getSlice(ret, G1Count, G2Count))
	if err != nil {
		return nil, err
	}

	return ct, nil
}

// HashToZp hashes a byte slice to an integer in Zp*.
func HashToZpStar(bytestring []byte) *big.Int {
	digest := sha256.Sum256(bytestring)
	bigint := new(big.Int).SetBytes(digest[:])
	bigint.Mod(bigint, new(big.Int).Sub(bn256.Order, big.NewInt(1)))
	bigint.Add(bigint, big.NewInt(1))
	return bigint
}

func HashToZp(bytestring []byte) *big.Int {
	digest := sha256.Sum256(bytestring)
	bigint := new(big.Int).SetBytes(digest[:])
	bigint.Mod(bigint, bn256.Order)
	return bigint
}
