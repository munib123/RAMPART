# CrossVul Fix Pair: Improper Access Control in go
**Pair ID:** 5378_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5378_0`)

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
	"reflect"
)

// Encrypter represents an encrypter which produces an encrypted JWE object.
type Encrypter interface {
	Encrypt(plaintext []byte) (*JsonWebEncryption, error)
	EncryptWithAuthData(plaintext []byte, aad []byte) (*JsonWebEncryption, error)
	SetCompression(alg CompressionAlgorithm)
}

// MultiEncrypter represents an encrypter which supports multiple recipients.
type MultiEncrypter interface {
	Encrypt(plaintext []byte) (*JsonWebEncryption, error)
	EncryptWithAuthData(plaintext []byte, aad []byte) (*JsonWebEncryption, error)
	SetCompression(alg CompressionAlgorithm)
	AddRecipient(alg KeyAlgorithm, encryptionKey interface{}) error
}

// A generic content cipher
type contentCipher interface {
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
 	"reflect"
 )
@@ -292,9 +293,15 @@
 	return obj, nil
 }
 
-// Decrypt and validate the object and return the plaintext.
+// Decrypt and validate the object and return the plaintext. Note that this
+// function does not support multi-recipient, if you desire multi-recipient
+// decryption use DecryptMulti instead.
 func (obj JsonWebEncryption) Decrypt(decryptionKey interface{}) ([]byte, error) {
 	headers := obj.mergedHeaders(nil)
+
+	if len(obj.recipients) > 1 {
+		return nil, errors.New("square/go-jose: too many recipients in payload; expecting only one")
+	}
 
 	if len(headers.Crit) > 0 {
 		return nil, fmt.Errorf("square/go-jose: unsupported crit header")
@@ -323,7 +330,65 @@
 	authData := obj.computeAuthData()
 
 	var plaintext []byte
-	for _, recipient := range obj.recipients {
+	recipient := obj.recipients[0]
+	recipientHeaders := obj.mergedHeaders(&recipient)
+
+	cek, err := decrypter.decryptKey(recipientHeaders, &recipient, generator)
+	if err == nil {
+		// Found a valid CEK -- let's try to decrypt.
+		plaintext, err = cipher.decrypt(cek, authData, parts)
+	}
+
+	if plaintext == nil {
+		return nil, ErrCryptoFailure
+	}
+
+	// The "zip" header parameter may only be present in the protected header.
+	if obj.protected.Zip != "" {
+		plaintext, err = decompress(obj.protected.Zip, plaintext)
+	}
+
+	return plaintext, err
+}
+
+// DecryptMulti decrypts and validates the object and returns the plaintexts,
+// with support for multiple recipients. It returns the index of the recipient
+// for which the decryption was successful, the merged headers for that recipient,
+// and the plaintext.
+func (obj JsonWebEncryption) DecryptMulti(decryptionKey interface{}) (int, JoseHeader, []byte, error) {
+	globalHeaders := obj.mergedHeaders(nil)
+
+	if len(globalHeaders.Crit) > 0 {
+		return -1, JoseHeader{}, nil, fmt.Errorf("square/go-jose: unsupported crit header")
+	}
+
+	decrypter, err := newDecrypter(decryptionKey)
+	if err != nil {
+		return -1, JoseHeader{}, nil, err
+	}
+
+	cipher := getContentCipher(globalHeaders.Enc)
+	if cipher == nil {
+		return -1, JoseHeader{}, nil, fmt.Errorf("square/go-jose: unsupported enc value '%s'", string(globalHeaders.Enc))
+	}
+
+	generator := randomKeyGenerator{
+		size: cipher.keySize(),
+	}
+
+	parts := &aeadParts{
+		iv:         obj.iv,
+		ciphertext: obj.ciphertext,
+		tag:        obj.tag,
+	}
+
+	authData := obj.computeAuthData()
+
+	index := -1
+	var plaintext []byte
+	var headers rawHeader
+
+	for i, recipient := range obj.recipients {
 		recipientHeaders := obj.mergedHeaders(&recipient)
 
 		cek, err := decrypter.decryptKey(recipientHeaders, &recipient, generator)
@@ -331,13 +396,15 @@
 			// Found a valid CEK -- let's try to decrypt.
 			plaintext, err = cipher.decrypt(cek, authData, parts)
 			if err == nil {
+				index = i
+				headers = recipientHeaders
 				break
 			}
 		}
 	}
 
-	if plaintext == nil {
-		return nil, ErrCryptoFailure
+	if plaintext == nil || err != nil {
+		return -1, JoseHeader{}, nil, ErrCryptoFailure
 	}
 
 	// The "zip" header parameter may only be present in the protected header.
@@ -345,5 +412,5 @@
 		plaintext, err = decompress(obj.protected.Zip, plaintext)
 	}
 
-	return plaintext, err
-}
+	return index, headers.sanitized(), plaintext, err
+}
```
