package paillier

import (
	"fmt"
	"math/big"
	"crypto/rand"
	"log"
	"github.com/paillier/util"
	"io"
	"github.com/kataras/go-errors"
)

var bigOne = big.NewInt(1)
var bigZero = big.NewInt(0)

type PaillierPrivateKey struct {
	PaillierKey
	L 		*big.Int 	// Let λ = lcm(p − 1, q − 1)
	DInvs 	*big.Int

	// Precomputed contains precomputed values that speed up private
	// operations, if available.
	Precomputed PrecomputedValues
}

//func (priv *PaillierPrivateKey) PaillierPrivateKey(n *big.Int, d *big.Int) () {
//
//}

type PaillierKey struct {
	N 			*big.Int
	G 			*big.Int
	NSquared	*big.Int
}

/*
 * To encrypt a message m ∈ Z*n , randomly chose r ∈ Z*n and compute the ciphertext c = g^m * r^N mod N^2
 * Hint: (g^m * r^N) mod N^2 = (g^m mod N^2 * r^N mod N^2) mod N^2
 */
func Encrypt(pk *PaillierKey, m *big.Int) (c *big.Int, err error) {
	if m.Cmp(pk.N) >= 0 {
		return nil, errors.New("m must be less than n")
	}

	r, err := randomZN(pk.N)
	if err != nil {
		return nil, err
	}

	c = new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Exp(pk.G, m, pk.NSquared),
				new(big.Int).Exp(r, pk.N, pk.NSquared)),
			pk.NSquared)

	return c, nil
}

// return a random integer in Zn
func randomZN(n *big.Int) (r *big.Int, err error) {
	r, err = rand.Int(rand.Reader, n)
	if err != nil {
		return nil, err
	}
	return
}

func GenerateKey(random io.Reader,bits int) (*PaillierPrivateKey, error)  {
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
			//break
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

	priv := new(PaillierPrivateKey)
	priv.L = d
	priv.DInvs = new(big.Int).ModInverse(d, n)
	priv.N = n
	priv.G = new(big.Int).Add(n, bigOne)
	priv.NSquared = new(big.Int).Mul(n, n)

	fmt.Printf("d * dInvs mod n = %d\n", new(big.Int).Mod(new(big.Int).Mul(priv.L, priv.DInvs), n))

	return priv, nil
}

type PrecomputedValues struct {
	Dp, Dq *big.Int // D mod (P-1) (or mod Q-1)
	Qinv   *big.Int // Q^-1 mod P

	NSquared 	*big.Int

	// CRTValues is used for the 3rd and subsequent primes. Due to a
	// historical accident, the CRT for the first two primes is handled
	// differently in PKCS#1 and interoperability is sufficiently
	// important that we mirror this.
	//CRTValues []CRTValue
}

// Precompute performs some calculations that speed up private key operations
// in the future.
func (priv *PaillierPrivateKey) Precompute() {
	if priv.Precomputed.Dp != nil {
		return
	}

	priv.Precomputed.NSquared = new(big.Int).Mul(priv.N, priv.N)

	/*priv.Precomputed.Dp = new(big.Int).Sub(priv.Primes[0], bigOne)
	priv.Precomputed.Dp.Mod(priv.D, priv.Precomputed.Dp)

	priv.Precomputed.Dq = new(big.Int).Sub(priv.Primes[1], bigOne)
	priv.Precomputed.Dq.Mod(priv.D, priv.Precomputed.Dq)

	priv.Precomputed.Qinv = new(big.Int).ModInverse(priv.Primes[1], priv.Primes[0])

	r := new(big.Int).Mul(priv.Primes[0], priv.Primes[1])
	priv.Precomputed.CRTValues = make([]CRTValue, len(priv.Primes)-2)
	for i := 2; i < len(priv.Primes); i++ {
		prime := priv.Primes[i]
		values := &priv.Precomputed.CRTValues[i-2]

		values.Exp = new(big.Int).Sub(prime, bigOne)
		values.Exp.Mod(priv.D, values.Exp)

		values.R = new(big.Int).Set(r)
		values.Coeff = new(big.Int).ModInverse(r, prime)

		r.Mul(r, prime)
	}*/
}