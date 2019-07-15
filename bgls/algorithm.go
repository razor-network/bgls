// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"math/big"
	"github.com/razor-network/go-sha3"
)


//AggSig holds paired sequences of keys and messages, and one signature
type AggSig struct {
	keys []Point
	msgs [][]byte
	sig  Point
}

//KeyGen generates a *big.Int and Point2
func KeyGen(curve CurveSystem) (*big.Int, Point, Point, error) {
	//Create private key
	x, err := rand.Int(rand.Reader, curve.GetG1Order())

	//Check for error
	if err != nil {
		return nil, nil, nil, err
	}

	//Compute public key
	W, X := ComputePublicKey(curve, x)

	return x, W, X, nil
}

//ComputePublicKey turns secret key into a public key of type Point2
func ComputePublicKey(curve CurveSystem, sk *big.Int) (Point, Point) {
	W := curve.GetG1().Mul(sk)
	X := curve.GetG2().Mul(sk)
	return W, X
}


// Creates a signature on a message with a private key, with prepending the public key to the message.
func Sign(curve CurveSystem, x *big.Int, v Point, msg []byte) Point {
	//Prepend public key to message
	m := msg

	//Hash message to element in G1
	h := hashToG1(curve, m)

	//Compute signature
	sigma := h.Mul(x)

	return sigma
}

// Checks that a single BLS signature is valid
func VerifySingleSignature(curve CurveSystem, sig Point, pubkey Point, m []byte) bool {
	//msg := append(pubkey.MarshalUncompressed(), m...)
	msg := m
	h := hashToG1(curve, msg)

	pairing1, _ := curve.Pair(sig, curve.GetG2())
	pairing2, _ := curve.Pair(h, pubkey)

	return pairing1.Equals(pairing2)
}

// Aggregates an array of signatures into one BGLS aggregate signature.
func AggregateSignatures(sigs []Point) Point {
	return AggregatePoints(sigs)
}

// Checks whether an aggregate is valid
func VerifyAggregateSignature(curve CurveSystem, aggsig Point, keys []Point, messages [][]byte) bool {
	//Verify that the number of keys and messages is equal
	if len(keys) != len(messages) {
		return false
	}

	//Prepend public key (optional modification proposed by Boneh et al.)
	/*msgs := make([][]byte, len(messages))
	for i := 0; i < len(msgs); i++ {
		msgs[i] = append(keys[i].MarshalUncompressed(), messages[i]...)
	}*/

	msgs := messages

	//array of hashes
	h_arr := make([]Point, len(keys)+1)
	//array of public keys
	v_arr := make([]Point, len(keys)+1)

	//Add signature and the negation of generator g2
	h_arr[0] = aggsig
	v_arr[0] = curve.GetG2().Mul(new(big.Int).SetInt64(-1))

	//Add all hashes and keys
	for i := 0; i < len(msgs); i++ {
		h_arr[i+1] = hashToG1(curve, msgs[i])
		v_arr[i+1] = keys[i]
	}

	aggPt, ok := curve.PairingProduct(h_arr, v_arr)
	if ok {
		return aggPt.Equals(curve.GetGTIdentity())
	}
	return ok
}

// Verify verifies an aggregate signature type.
func (a *AggSig) Verify(curve CurveSystem) bool {
	return VerifyAggregateSignature(curve, a.sig, a.keys, a.msgs)
}

func hashToG1(curve CurveSystem, message []byte) Point {
	h := solsha3.SoliditySHA3(message)
	return curve.GetG1().Mul(new(big.Int).SetBytes(h))
}
