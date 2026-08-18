# CrossVul Fix Pair: Inadequate Encryption Strength in go
**Pair ID:** 5377_2
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5377_2`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```go
Lines 16-51 of the vulnerable file.


package josecipher

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/binary"
)

// DeriveECDHES derives a shared encryption key using ECDH/ConcatKDF as described in JWE/JWA.
func DeriveECDHES(alg string, apuData, apvData []byte, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, size int) []byte {
	// algId, partyUInfo, partyVInfo inputs must be prefixed with the length
	algID := lengthPrefixed([]byte(alg))
	ptyUInfo := lengthPrefixed(apuData)
	ptyVInfo := lengthPrefixed(apvData)

	// suppPubInfo is the encoded length of the output size in bits
	supPubInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(supPubInfo, uint32(size)*8)

	z, _ := priv.PublicKey.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	reader := NewConcatKDF(crypto.SHA256, z.Bytes(), algID, ptyUInfo, ptyVInfo, supPubInfo, []byte{})

	key := make([]byte, size)

	// Read on the KDF will never fail
	_, _ = reader.Read(key)
	return key
}

func lengthPrefixed(data []byte) []byte {
	out := make([]byte, len(data)+4)
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)
	return out
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,6 +33,10 @@
 	supPubInfo := make([]byte, 4)
 	binary.BigEndian.PutUint32(supPubInfo, uint32(size)*8)
 
+	if !priv.PublicKey.Curve.IsOnCurve(pub.X, pub.Y) {
+		panic("public key not on same curve as private key")
+	}
+
 	z, _ := priv.PublicKey.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
 	reader := NewConcatKDF(crypto.SHA256, z.Bytes(), algID, ptyUInfo, ptyVInfo, supPubInfo, []byte{})
 
```
