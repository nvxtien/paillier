package paillier

import (
	"fmt"
	"math/big"
	"crypto/rand"
	"log"
	"github.com/paillier/util"
	"io"
	"errors"
)

var bigOne = big.NewInt(1)
var bigZero = big.NewInt(0)

type PrivateKey struct {
	PublicKey
	L	*big.Int 	// Let λ = lcm(p − 1, q − 1)

	// Precomputed contains precomputed values that speed up private
	// operations, if available.
	Precomputed PrecomputedValues
}

type PublicKey struct {
	N			*big.Int
	NSquared	*big.Int
	G 			*big.Int
}

// return a random integer in Z*n^2
func randomZStarNSquared(nSquared *big.Int) (r *big.Int, err error) {
	for {
		r, err = rand.Int(rand.Reader, nSquared)
		if err != nil {
			return nil, err
		}

		if new(big.Int).GCD(nil, nil, r, nSquared).Cmp(bigOne) == 0 {
			break
		}
	}

	return
}

func GenerateKey(random io.Reader,bits int) (*PrivateKey, error)  {
	var p, q *big.Int
	var err error

	for {
		p, err = rand.Prime(random, bits/2)
		if err != nil{
			log.Fatalf("Can't generate %d-bit prime: %v", bits, err)
		}

		q, err = rand.Prime(random, bits/2)
		if err != nil{
			log.Fatalf("Can't generate %d-bit prime: %v", bits, err)
		}

		minprm := util.BigMin(p, q)
		maxprm := util.BigMax(p, q)
		//Make the smallest prime p, maximum q
		p = minprm
		q = maxprm

		// Now verify that p-1 does not divide q
		if new(big.Int).Mod(q, new(big.Int).Sub(p, bigOne)).Cmp(bigZero) == 0 {
			fmt.Print("p-1 does divide q")
			continue
		}

		// Make sure that primes is pairwise unequal
		if p.Cmp(q) == 0 {
			continue
		}

		break
	}

	fmt.Printf("p: %d\n", p)
	fmt.Printf("q: %d\n", q)

	n := new(big.Int).Mul(p, q)
	fmt.Printf("n: %d\n", n)

	pminus1 := new(big.Int).Sub(p, bigOne)
	fmt.Printf("p-1: %d\n", pminus1)

	qminus1 := new(big.Int).Sub(q, bigOne)
	fmt.Printf("q-1: %d\n", qminus1)

	phi := new(big.Int).Mul(pminus1, qminus1)

	//Now we can calculate the Carmichael's function for n
	//i.e., lcm(p-1,q-1)
	//Note that phi(n)=gcd(p-1,q-1)*lcm(p-1,q-1)
	gcd := new(big.Int).GCD(nil, nil, pminus1, qminus1)
	fmt.Printf("gcd: %d\n", gcd)

	d := new(big.Int).Div(phi, gcd)
	fmt.Printf("lcm: %d\n", d)

	priv := new(PrivateKey)
	priv.L = d
	priv.N = n
	priv.NSquared = new(big.Int).Mul(n, n)
	priv.G, err = randomZStarNSquared(priv.NSquared)
	if err != nil {
		return nil, err
	}

	priv.Precompute()

	return priv, nil
}

// return a random integer in Z*n
func randomZStarN(n *big.Int) (r *big.Int, err error) {
	for {
		r, err = rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		if new(big.Int).GCD(nil, nil, r, n).Cmp(bigOne) == 0 {
			break
		}
	}

	return
}

/*
 * To encrypt a message m ∈ Zn , randomly chose r ∈ Z*n and compute the ciphertext c = g^m * r^N mod N^2
 * Hint: (g^m * r^N) mod N^2 = (g^m mod N^2 * r^N mod N^2) mod N^2
 */
func Encrypt(pub *PublicKey, m *big.Int) (c *big.Int, err error) {
	if m.Cmp(pub.N) >= 0 {
		return nil, errors.New("m must be less than n")
	}

	r, err := randomZStarN(pub.N)
	if err != nil {
		return nil, err
	}

	c = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(pub.G, m, pub.NSquared),
			new(big.Int).Exp(r, pub.N, pub.NSquared)),
		pub.NSquared)

	return c, nil
}

/*
 * Compute m ≡ L(c^λ(n) mod n^2) * k^-1 mod n
 */
func Decrypt(priv *PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priv.NSquared) >= 0 {
		return nil, errors.New("c must be less than n squared")
	}
	u  := new(big.Int).Exp(c, priv.L, priv.NSquared)
	Lu := new(big.Int).Div(new(big.Int).Sub(u, bigOne), priv.N)
	m = new(big.Int).Mod(new(big.Int).Mul(Lu, priv.Precomputed.Mu), priv.N)
	return
}

// D[E(m1)·E(m2) mod n^2] ≡ m1 + m2 mod n
func AddCipher(pub *PublicKey, c1, c2 *big.Int) (c *big.Int, err error) {
	c = new(big.Int).Mod(new(big.Int).Mul(c1, c2), pub.NSquared)
	return c, nil
}

type PrecomputedValues struct {
	Mu 	*big.Int
}

// Precompute performs some calculations that speed up private key operations
// in the future.
func (priv *PrivateKey) Precompute() {
	if priv.Precomputed.Mu != nil {
		return
	}

	// Define L(u) = (u – 1)/n
	// Compute L(g^λ(n) mod n^2) = k
	// Compute μ ≡ k^–1 mod n
	u := new(big.Int).Exp(priv.G, priv.L, priv.NSquared)
	k := new(big.Int).Div(u.Sub(u, bigOne), priv.N)
	priv.Precomputed.Mu = new(big.Int).ModInverse(k, priv.N)
}