# CrossVul Fix Pair: Integer Overflow or Wraparound in go
**Pair ID:** 5379_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5379_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```go
Lines 65-105 of the vulnerable file.

type cbcAEAD struct {
	hash         func() hash.Hash
	authtagBytes int
	integrityKey []byte
	blockCipher  cipher.Block
}

func (ctx *cbcAEAD) NonceSize() int {
	return nonceBytes
}

func (ctx *cbcAEAD) Overhead() int {
	// Maximum overhead is block size (for padding) plus auth tag length, where
	// the length of the auth tag is equivalent to the key size.
	return ctx.blockCipher.BlockSize() + ctx.authtagBytes
}

// Seal encrypts and authenticates the plaintext.
func (ctx *cbcAEAD) Seal(dst, nonce, plaintext, data []byte) []byte {
	// Output buffer -- must take care not to mangle plaintext input.
	ciphertext := make([]byte, len(plaintext)+ctx.Overhead())[:len(plaintext)]
	copy(ciphertext, plaintext)
	ciphertext = padBuffer(ciphertext, ctx.blockCipher.BlockSize())

	cbc := cipher.NewCBCEncrypter(ctx.blockCipher, nonce)

	cbc.CryptBlocks(ciphertext, ciphertext)
	authtag := ctx.computeAuthTag(data, nonce, ciphertext)

	ret, out := resize(dst, len(dst)+len(ciphertext)+len(authtag))
	copy(out, ciphertext)
	copy(out[len(ciphertext):], authtag)

	return ret
}

// Open decrypts and authenticates the ciphertext.
func (ctx *cbcAEAD) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(ciphertext) < ctx.authtagBytes {
		return nil, errors.New("square/go-jose: invalid ciphertext (too short)")
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,7 +82,7 @@
 // Seal encrypts and authenticates the plaintext.
 func (ctx *cbcAEAD) Seal(dst, nonce, plaintext, data []byte) []byte {
 	// Output buffer -- must take care not to mangle plaintext input.
-	ciphertext := make([]byte, len(plaintext)+ctx.Overhead())[:len(plaintext)]
+	ciphertext := make([]byte, uint64(len(plaintext))+uint64(ctx.Overhead()))[:len(plaintext)]
 	copy(ciphertext, plaintext)
 	ciphertext = padBuffer(ciphertext, ctx.blockCipher.BlockSize())
 
@@ -91,7 +91,7 @@
 	cbc.CryptBlocks(ciphertext, ciphertext)
 	authtag := ctx.computeAuthTag(data, nonce, ciphertext)
 
-	ret, out := resize(dst, len(dst)+len(ciphertext)+len(authtag))
+	ret, out := resize(dst, uint64(len(dst))+uint64(len(ciphertext))+uint64(len(authtag)))
 	copy(out, ciphertext)
 	copy(out[len(ciphertext):], authtag)
 
@@ -128,7 +128,7 @@
 		return nil, err
 	}
 
-	ret, out := resize(dst, len(dst)+len(plaintext))
+	ret, out := resize(dst, uint64(len(dst))+uint64(len(plaintext)))
 	copy(out, plaintext)
 
 	return ret, nil
@@ -136,12 +136,12 @@
 
 // Compute an authentication tag
 func (ctx *cbcAEAD) computeAuthTag(aad, nonce, ciphertext []byte) []byte {
-	buffer := make([]byte, len(aad)+len(nonce)+len(ciphertext)+8)
+	buffer := make([]byte, uint64(len(aad))+uint64(len(nonce))+uint64(len(ciphertext))+8)
 	n := 0
 	n += copy(buffer, aad)
 	n += copy(buffer[n:], nonce)
 	n += copy(buffer[n:], ciphertext)
-	binary.BigEndian.PutUint64(buffer[n:], uint64(len(aad)*8))
+	binary.BigEndian.PutUint64(buffer[n:], uint64(len(aad))*8)
 
 	// According to documentation, Write() on hash.Hash never fails.
 	hmac := hmac.New(ctx.hash, ctx.integrityKey)
@@ -153,8 +153,8 @@
 // resize ensures the the given slice has a capacity of at least n bytes.
 // If the capacity of the slice is less than n, a new slice is allocated
 // and the existing data will be copied.
-func resize(in []byte, n int) (head, tail []byte) {
-	if cap(in) >= n {
+func resize(in []byte, n uint64) (head, tail []byte) {
+	if uint64(cap(in)) >= n {
 		head = in[:n]
 	} else {
 		head = make([]byte, n)
@@ -168,7 +168,7 @@
 // Apply padding
 func padBuffer(buffer []byte, blockSize int) []byte {
 	missing := blockSize - (len(buffer) % blockSize)
-	ret, out := resize(buffer, len(buffer)+missing)
+	ret, out := resize(buffer, uint64(len(buffer))+uint64(missing))
 	padding := bytes.Repeat([]byte{byte(missing)}, missing)
 	copy(out, padding)
 	return ret
```
