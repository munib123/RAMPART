# CrossVul Fix Pair: Inadequate Encryption Strength in go
**Pair ID:** 5377_0
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5377_0`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```go
Lines 353-393 of the vulnerable file.

	headers := rawHeader{
		Epk: &JsonWebKey{
			Key: &priv.PublicKey,
		},
	}

	return out, headers, nil
}

// Decrypt the given payload and return the content encryption key.
func (ctx ecDecrypterSigner) decryptKey(headers rawHeader, recipient *recipientInfo, generator keyGenerator) ([]byte, error) {
	if headers.Epk == nil {
		return nil, errors.New("square/go-jose: missing epk header")
	}

	publicKey, ok := headers.Epk.Key.(*ecdsa.PublicKey)
	if publicKey == nil || !ok {
		return nil, errors.New("square/go-jose: invalid epk header")
	}

	apuData := headers.Apu.bytes()
	apvData := headers.Apv.bytes()

	deriveKey := func(algID string, size int) []byte {
		return josecipher.DeriveECDHES(algID, apuData, apvData, ctx.privateKey, publicKey, size)
	}

	var keySize int

	switch KeyAlgorithm(headers.Alg) {
	case ECDH_ES:
		// ECDH-ES uses direct key agreement, no key unwrapping necessary.
		return deriveKey(string(headers.Enc), generator.keySize()), nil
	case ECDH_ES_A128KW:
		keySize = 16
	case ECDH_ES_A192KW:
		keySize = 24
	case ECDH_ES_A256KW:
		keySize = 32
	default:
		return nil, ErrUnsupportedAlgorithm
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -370,6 +370,10 @@
 		return nil, errors.New("square/go-jose: invalid epk header")
 	}
 
+	if !ctx.privateKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
+		return nil, errors.New("square/go-jose: invalid public key in epk header")
+	}
+
 	apuData := headers.Apu.bytes()
 	apvData := headers.Apv.bytes()
 
```
