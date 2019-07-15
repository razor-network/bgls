package main

import (
	"crypto/rsa"
	"fmt"
	"crypto/rand"
	"os"
	"math/big"
  "github.com/razor-network/bgls/bgls"
)

func bls() {
	curve := CurveSystem(Altbn128)

	//generate key
	x, _, X, _ := KeyGen(curve)

	message := []byte("TEST")

	//create signature
	sig := Sign(curve, x, X, message)

	//verify
	fmt.Println("verification:", VerifySingleSignature(curve, sig, X, message))

	fmt.Println("sig:", sig.ToAffineCoords())
	fmt.Println("message:", bytestohex(message))
	fmt.Println("key", X.ToAffineCoords())
}

func bgls() {
	number_of_signers := 10
	curve := CurveSystem(Altbn128)

	var sigs []Point
	var publickeys []Point
	var msgs [][]byte

	//Initialization
	for i := 0; i < number_of_signers; i++ {
		//generate key
		x, _, X, _ := KeyGen(curve)

		//create message
		message := []byte("TEST" + string(i))

		//create signature
		sig := Sign(curve, x, X, message)

		//save for later
		publickeys = append(publickeys, X)
		msgs = append(msgs, message)
		sigs = append(sigs, sig)
	}

	//aggregate signature
	aggsig := AggregateSignatures(sigs)

	//verify
	fmt.Println(VerifyAggregateSignature(curve, aggsig, publickeys, msgs))

	//print signature
	fmt.Println("sig:", aggsig.ToAffineCoords())

	//print keys
	for j := 0; j < len(publickeys); j++ {
		fmt.Println("key:", j, publickeys[j].ToAffineCoords())
	}

	//print messages
	for k := 0; k < len(publickeys); k++ {
		fmt.Println("msg:", k, bytestohex(msgs[k]))
	}
}
