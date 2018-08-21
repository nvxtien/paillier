package paillier

import (
	"testing"
	"crypto/rand"
	"math/big"
	"fmt"
)

func TestKeyGeneration(t *testing.T) {
	size := 2048

	priv, err := GenerateKey(rand.Reader, size)
	if err != nil {
		t.Errorf("failed to generate key")
	}
	if bits := priv.N.BitLen(); bits != size {
		t.Errorf("key too short (%d vs %d)", bits, size)
	}
	testKeyBasics(t, priv)

	testAdd(t, priv)
}

func testKeyBasics(t *testing.T, priv *PrivateKey) {
	/*if err := priv.Validate(); err != nil {
		t.Errorf("Validate() failed: %s", err)
	}
	if priv.D.Cmp(priv.N) > 0 {
		t.Errorf("private exponent too large")
	}
*/
	//priv, _ = GenerateKey(rand.Reader, 1024)
	pub := &priv.PublicKey
	m := big.NewInt(42)
	c, _ :=  Encrypt(pub, m)

	m2, err := Decrypt(priv, c)
	if err != nil {
		t.Errorf("error while decrypting: %s", err)
		return
	}

	if m.Cmp(m2) != 0 {
		t.Errorf("unknown error while decrypting")
	}
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

	fmt.Printf("ciphertext is %d\n", c)

	if c.Cmp(big.NewInt(4624)) != 0 {
		t.Errorf("encrypt wrongly")
	}
}

func testAdd(t *testing.T, priv *PrivateKey) {
	c1,_ := Encrypt(&priv.PublicKey, big.NewInt(32))
	c2,_ := Encrypt(&priv.PublicKey, big.NewInt(17))

	c,_ := AddCipher(&priv.PublicKey, c1, c2)

	m,_ := Decrypt(priv, c)

	if m.Cmp(big.NewInt(32 + 17)) != 0 {
		t.Errorf("add wrongly")
	}

	fmt.Printf("plaintext is %d\n", m)

}