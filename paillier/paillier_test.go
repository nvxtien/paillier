package paillier

import (
	"testing"
	"crypto/rand"
)

func TestKeyGeneration(t *testing.T) {
	size := 2048
	if testing.Short() {
		size = 128
	}
	priv, err := GenerateKey(rand.Reader, size)
	if err != nil {
		t.Errorf("failed to generate key")
	}
	if bits := priv.N.BitLen(); bits != size {
		t.Errorf("key too short (%d vs %d)", bits, size)
	}
	//testKeyBasics(t, priv)
}