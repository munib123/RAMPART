# CrossVul Fix Pair: Allocation of File Descriptors or Handles Without Limits or Throttling in go
**Pair ID:** 39_2
**Vulnerability Class:** Allocation of File Descriptors or Handles Without Limits or Throttling
**CWE:** CWE-774
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `39_2`)

## Vulnerability Information & PoC

## Description
Allocation of File Descriptors or Handles Without Limits or Throttling - This can cause the product to consume all available file descriptors or handles, which can prevent other processes from performing critical file processing operations.

## Vulnerable Code
```go
Lines 44-84 of the vulnerable file.

// SHA256 sum (if set) of the provided io.Reader at EOF.
func NewReader(src io.Reader, size int64, md5Hex, sha256Hex string) (*Reader, error) {
	if _, ok := src.(*Reader); ok {
		return nil, errNestedReader
	}

	sha256sum, err := hex.DecodeString(sha256Hex)
	if err != nil {
		return nil, SHA256Mismatch{}
	}

	md5sum, err := hex.DecodeString(md5Hex)
	if err != nil {
		return nil, BadDigest{}
	}

	var sha256Hash hash.Hash
	if len(sha256sum) != 0 {
		sha256Hash = sha256.New()
	}

	return &Reader{
		md5sum:     md5sum,
		sha256sum:  sha256sum,
		src:        io.LimitReader(src, size),
		size:       size,
		md5Hash:    md5.New(),
		sha256Hash: sha256Hash,
	}, nil
}

func (r *Reader) Read(p []byte) (n int, err error) {
	n, err = r.src.Read(p)
	if n > 0 {
		r.md5Hash.Write(p[:n])
		if r.sha256Hash != nil {
			r.sha256Hash.Write(p[:n])
		}
	}

	// At io.EOF verify if the checksums are right.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,11 +61,13 @@
 	if len(sha256sum) != 0 {
 		sha256Hash = sha256.New()
 	}
-
+	if size >= 0 {
+		src = io.LimitReader(src, size)
+	}
 	return &Reader{
 		md5sum:     md5sum,
 		sha256sum:  sha256sum,
-		src:        io.LimitReader(src, size),
+		src:        src,
 		size:       size,
 		md5Hash:    md5.New(),
 		sha256Hash: sha256Hash,
```
