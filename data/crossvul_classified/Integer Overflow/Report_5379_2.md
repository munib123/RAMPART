# CrossVul Fix Pair: Integer Overflow or Wraparound in go
**Pair ID:** 5379_2
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5379_2`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```go
Lines 15-55 of the vulnerable file.

 */

package josecipher

import (
	"crypto"
	"encoding/binary"
	"hash"
	"io"
)

type concatKDF struct {
	z, info []byte
	i       uint32
	cache   []byte
	hasher  hash.Hash
}

// NewConcatKDF builds a KDF reader based on the given inputs.
func NewConcatKDF(hash crypto.Hash, z, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo []byte) io.Reader {
	buffer := make([]byte, len(algID)+len(ptyUInfo)+len(ptyVInfo)+len(supPubInfo)+len(supPrivInfo))
	n := 0
	n += copy(buffer, algID)
	n += copy(buffer[n:], ptyUInfo)
	n += copy(buffer[n:], ptyVInfo)
	n += copy(buffer[n:], supPubInfo)
	copy(buffer[n:], supPrivInfo)

	hasher := hash.New()

	return &concatKDF{
		z:      z,
		info:   buffer,
		hasher: hasher,
		cache:  []byte{},
		i:      1,
	}
}

func (ctx *concatKDF) Read(out []byte) (int, error) {
	copied := copy(out, ctx.cache)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
 
 // NewConcatKDF builds a KDF reader based on the given inputs.
 func NewConcatKDF(hash crypto.Hash, z, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo []byte) io.Reader {
-	buffer := make([]byte, len(algID)+len(ptyUInfo)+len(ptyVInfo)+len(supPubInfo)+len(supPrivInfo))
+	buffer := make([]byte, uint64(len(algID))+uint64(len(ptyUInfo))+uint64(len(ptyVInfo))+uint64(len(supPubInfo))+uint64(len(supPrivInfo)))
 	n := 0
 	n += copy(buffer, algID)
 	n += copy(buffer[n:], ptyUInfo)
```
