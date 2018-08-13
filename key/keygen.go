package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"github.com/ethereum/go-ethereum/common/math"
	"math/big"
)

var bigOne = big.NewInt(1)

func main()  {
	//rnd := rand.Reader
	//fmt.Printf("%s", rnd)

	bits := 1024

	p := new(KeyGen)
	priv, err := p.GenerateKey(bits)


	fmt.Printf("d: %d\n", priv.d)
	fmt.Printf("dInvs: %d\n", priv.dInvs)

	if err != nil{
		log.Fatalf("Can't generate %d-bit prime: %v", bits, err)
	}

	for n := 1024; n < 1027; n++ {
		p, err := rand.Prime(rand.Reader, n)
		//log.Fatalf("Can't generate %d-bit prime: %v", n, err)
		if err != nil {
			log.Fatalf("Can't generate %d-bit prime: %v", n, err)
		}
		if p.BitLen() != n {
			log.Fatalf("%v is not %d-bit", p, n)
		}
		if !p.ProbablyPrime(32) {
			log.Fatalf("%v is not prime", p)
		}

		//fmt.Printf("test\n%d\n", p)
	}
}

type KeyGen struct {

}

func (k *KeyGen) GenerateKey(bits int) (*PaillierPrivateKey, error)  {
	var p, q *big.Int
	var err error

	for {
		p, err = rand.Prime(rand.Reader, bits)
		if err != nil{
			log.Fatalf("Can't generate %d-bit prime: %v", bits, err)
		}

		q, err = rand.Prime(rand.Reader, bits)
		if err != nil{
			log.Fatalf("Can't generate %d-bit prime: %v", bits, err)
		}

		minprm := math.BigMin(p, q)
		maxprm := math.BigMax(p, q)
		//Make the smallest prime p, maximum q
		p = minprm
		q = maxprm

		// Now verify that  p-1 does not divide q

		if new(big.Int).Mod(q, new(big.Int).Sub(p, big.NewInt(1))).Cmp(big.NewInt(0)) != 0 {
			break
		}

		fmt.Print("p-1 does divide q")
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
	priv.d = d
	priv.dInvs = new(big.Int).ModInverse(d, n)
	priv.n = n
	priv.g = new(big.Int).Add(n, bigOne)

	fmt.Printf("d * dInvs mod n = %d\n", new(big.Int).Mod(new(big.Int).Mul(priv.d, priv.dInvs), n))

	return priv, nil
}



type PaillierPrivateKey struct {
	PaillierKey
	d 		*big.Int
	dInvs 	*big.Int

}

//func (priv *PaillierPrivateKey) PaillierPrivateKey(n *big.Int, d *big.Int) () {
//
//}

type PaillierKey struct {
	n 	*big.Int
	g 	*big.Int
}