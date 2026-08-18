# CrossVul Fix Pair: Improper Access Control in go
**Pair ID:** 5378_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5378_3`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```go
Lines 2-42 of the vulnerable file.

 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
)

// NonceSource represents a source of random nonces to go into JWS objects
type NonceSource interface {
	Nonce() (string, error)
}

// Signer represents a signer which takes a payload and produces a signed JWS object.
type Signer interface {
	Sign(payload []byte) (*JsonWebSignature, error)
	SetNonceSource(source NonceSource)
	SetEmbedJwk(embed bool)
}

// MultiSigner represents a signer which supports multiple recipients.
type MultiSigner interface {
	Sign(payload []byte) (*JsonWebSignature, error)
	SetNonceSource(source NonceSource)
	SetEmbedJwk(embed bool)
	AddRecipient(alg SignatureAlgorithm, signingKey interface{}) error
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 import (
 	"crypto/ecdsa"
 	"crypto/rsa"
+	"errors"
 	"fmt"
 )
 
@@ -193,13 +194,46 @@
 }
 
 // Verify validates the signature on the object and returns the payload.
+// Note that this function does not support multi-signature, if you desire
+// multi-sig verification use VerifyMulti instead.
 func (obj JsonWebSignature) Verify(verificationKey interface{}) ([]byte, error) {
 	verifier, err := newVerifier(verificationKey)
 	if err != nil {
 		return nil, err
 	}
 
-	for _, signature := range obj.Signatures {
+	if len(obj.Signatures) > 1 {
+		return nil, errors.New("square/go-jose: too many signatures in payload; expecting only one")
+	}
+
+	signature := obj.Signatures[0]
+	headers := signature.mergedHeaders()
+	if len(headers.Crit) > 0 {
+		// Unsupported crit header
+		return nil, ErrCryptoFailure
+	}
+
+	input := obj.computeAuthData(&signature)
+	alg := SignatureAlgorithm(headers.Alg)
+	err = verifier.verifyPayload(input, signature.Signature, alg)
+	if err == nil {
+		return obj.payload, nil
+	}
+
+	return nil, ErrCryptoFailure
+}
+
+// VerifyMulti validates (one of the multiple) signatures on the object and
+// returns the index of the signature that was verified, along with the signature
+// object and the payload. We return the signature and index to guarantee that
+// callers are getting the verified value.
+func (obj JsonWebSignature) VerifyMulti(verificationKey interface{}) (int, Signature, []byte, error) {
+	verifier, err := newVerifier(verificationKey)
+	if err != nil {
+		return -1, Signature{}, nil, err
+	}
+
+	for i, signature := range obj.Signatures {
 		headers := signature.mergedHeaders()
 		if len(headers.Crit) > 0 {
 			// Unsupported crit header
@@ -210,9 +244,9 @@
 		alg := SignatureAlgorithm(headers.Alg)
 		err := verifier.verifyPayload(input, signature.Signature, alg)
 		if err == nil {
-			return obj.payload, nil
-		}
-	}
-
-	return nil, ErrCryptoFailure
-}
+			return i, signature, obj.payload, nil
+		}
+	}
+
+	return -1, Signature{}, nil, ErrCryptoFailure
+}
```
