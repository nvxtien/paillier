package paillier

import (
	"testing"
	"crypto/rand"
	"math/big"
	"fmt"
)

func TestKeyGeneration(t *testing.T) {
	size := 2048
	//if testing.Short() {
	//	size = 128
	//}
	priv, err := GenerateKey(rand.Reader, size)
	if err != nil {
		t.Errorf("failed to generate key")
	}
	if bits := priv.N.BitLen(); bits != size {
		t.Errorf("key too short (%d vs %d)", bits, size)
	}
	//testKeyBasics(t, priv)
}

func TestEncryption(t *testing.T) {
	m := big.NewInt(42)
	r := big.NewInt(23)

	fmt.Printf("\n\n%d\n", m.BitLen())

	N := big.NewInt(77)
	G := big.NewInt(5652)
	NSquared := new(big.Int).Mul(N, N)

	fmt.Printf("N %d\n", N)
	fmt.Printf("NSquared %d\n", NSquared)
	fmt.Printf("G %d\n", G)

	fmt.Printf("r %d\n", r)

	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(G, m, NSquared),
			new(big.Int).Exp(r, N, NSquared)),
		NSquared)

	fmt.Printf("c %d\n", c)

	if c.Cmp(big.NewInt(4624)) != 0 {
		t.Errorf("encrypt wrongly")
	}
}