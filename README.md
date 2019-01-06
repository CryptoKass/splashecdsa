...

temp readme: 

This is a wrapper for the built in ecdsa, for the Splash ledger that adds:
- public key reconstruction from the signature.
- Mild support for multi signature applications.
- Generic address generation.

---

# Reconstruction Example 
```
C := elliptic.P256()

key, _ := splashecdsa.GenerateKeys(C)
fmt.Printf("key X: %#x\nkey Y: %#x\n", key.X, key.Y)

hashedMessage := sha256.Sum256([]byte("hello"))
sig, _ := key.Sign(hashedMessage[:])

pub := sig.ReconstructPublicKey(hashedMessage[:], C)
fmt.Printf("key X: %#x\nkey Y: %#x\n", pub.X, pub.Y)

fmt.Println("reconstruction success:", pub.X.Cmp(key.X) == 0)
```

---

Todo:
- add tests.
- extend multisig.