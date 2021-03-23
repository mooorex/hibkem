package HIBKEM

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestHIBKEM(t *testing.T) {
	params, msk, _ := Setup(rand.Reader, 100)
	var id1 = params.RootID + string("1001")
	var id2 = params.RootID + string("10011")
	var id3 = params.RootID + string("10011111111101011111111111111111111111111")

	c1sk, err := KeyGen(rand.Reader, params, msk, id1)
	if err != nil {
		t.Fatal(err)
	}
	c2sk, err := KeyGen(rand.Reader, params, c1sk, id2)
	if err != nil {
		t.Fatal(err)
	}
	c3sk, err := KeyGen(rand.Reader, params, c1sk, id3)
	if err != nil {
		t.Fatal(err)
	}

	symk1, ct1, _ := Encapsulate(rand.Reader, params, id1)
	symk2, ct2, _ := Encapsulate(rand.Reader, params, id2)
	symk3, ct3, _ := Encapsulate(rand.Reader, params, id3)

	symk1p := Decapsulate(c1sk, ct1)
	symk2p := Decapsulate(c2sk, ct2)
	symk3p := Decapsulate(c3sk, ct3)

	if bytes.Equal(symk1.Marshal(), symk1p.Marshal()) &&
		bytes.Equal(symk2.Marshal(), symk2p.Marshal()) &&
		bytes.Equal(symk3.Marshal(), symk3p.Marshal()) {
		t.Log("Success!!!")
	} else {
		t.Fatalf("emmmm!")
	}

}

func TestPuncture(t *testing.T) {
	params, msk, _ := Setup(rand.Reader, 100)

	var id1 = params.RootID + string("1")
	var id2 = params.RootID + string("00")
	var id3 = params.RootID + string("01")

	newset := make([]*PrivateKey, 0)
	older := &PrivateKey{}

	older = msk
	newset = append(newset, older)

	older = &PrivateKey{}
	older, _ = KeyGen(rand.Reader, params, msk, id1)
	newset = append(newset, older)

	older = &PrivateKey{}
	older, _ = KeyGen(rand.Reader, params, msk, id2)
	newset = append(newset, older)

	t.Log("punctures tring:", id3)

	t.Log("original set length:", len(newset))
	for i, item := range newset {
		t.Log("original set:", i, item.ID)
	}

	s1, s2 := PunctureTree(params, newset, id3)

	t.Log("punctured set length:", len(s1))
	for i, item := range s1 {
		t.Log("punctured set:", i, item.ID)
	}

	t.Log("set prime length:", len(s2))
	for i, item := range s2 {
		t.Log("set prime:", i, item.ID)
	}
}
