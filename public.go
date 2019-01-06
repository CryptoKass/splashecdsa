// MIT License

// Copyright (c) 2019 Kassius Barker <kasscrypto@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package splashecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/CryptoKass/splashecdsa/ecmath"
)

// SplashPublicKey is a wrapper for ecdsa.PublicKey which adds
// some useful methods like ToBytes(), FromBytes() and QuickCheck()
type SplashPublicKey ecdsa.PublicKey

// Bytes concatonates the Public keys x and y values
// and returns the resulting byte array. For a smaller
// byte array see @CompressedBytes.
func (pub *SplashPublicKey) Bytes() (buf []byte) {
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	buf = append(x, y...)
	return
}

// CompressedBytes returns a compress version of the
// public key that can be reconstructed using
// @SetCompressedBytes.
//
// CompressedBytes are typically of length (n/2)+1 where n
// is the length of normal Bytes(). It is more expensive to
// Generate compress/reconstruct from CompressedBytes.
func (pub *SplashPublicKey) CompressedBytes() (buf []byte) {
	// get the two possible y values
	_, y1 := ecmath.GetY(pub.X, pub.Curve.Params())

	// set v flag
	v := byte(0x0)
	if y1.Cmp(pub.Y) == 0 {
		v = byte(0x1)
	}

	//get X bytes
	x := pub.X.Bytes()

	// append flag:
	buf = append([]byte{v}, x...)
	return
}

// SetBytes decodes the buf and stores the values in the
// pub X and Y
func (pub *SplashPublicKey) SetBytes(buf []byte) {
	bigX := new(big.Int)
	bigY := new(big.Int)
	bigX.SetBytes(buf[:32])
	bigY.SetBytes(buf[32:])

	pub.X = bigX
	pub.Y = bigY
	pub.Curve = elliptic.P256()
	return
}

// QuickCheck quickly checks that the public key is
// in accordance with splashs ecdsa curve
func (pub *SplashPublicKey) QuickCheck(curve elliptic.Curve) bool {
	if pub.Curve != curve {
		return false
	}
	if !curve.IsOnCurve(pub.X, pub.Y) {
		return false
	}
	return false
}

// Verify verifies a SplashSignature of the hash belongs to this
// SplashPublicKey
func (pub *SplashPublicKey) Verify(hash []byte, sig SplashSignature) bool {
	ecPub := ecdsa.PublicKey(*pub)
	return ecdsa.Verify(&ecPub, hash, sig.R, sig.S)
}
