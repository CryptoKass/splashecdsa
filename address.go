package splashecdsa

import (
	"crypto/sha256"
)

func (pub *SplashPublicKey) GetAddress(compressed bool) []byte {
	buf := pub.Bytes()
	v := byte(0x0) // compression flag
	z := byte(0x0) // mutlisig flag
	if compressed {
		buf = pub.CompressedBytes()
		v = byte(0x1)
	}
	addrRaw := sha256.Sum256(buf)
	return append([]byte{v, z}, addrRaw[:20]...)
}

func (priv *SplashPrivateKey) GetAddress(compressed bool) []byte {
	pub := priv.GetPublicKey()
	return pub.GetAddress(compressed)
}

func IsAddressCompressed(addr []byte) bool {
	v := addr[0]
	if v == 0x0 {
		return false
	}
	return true
}

func IsMultiSigAddress(addr []byte) bool {
	z := addr[1]
	if z == 0x0 {
		return false
	}
	return true
}

// IsAddressValid is a quick check to ensure
// address is of a reasonable length.
func IsAddressValid(addr []byte) bool {
	l := len(addr)
	return (l >= 20 && l <= 64)
}
