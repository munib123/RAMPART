# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in go
**Pair ID:** 1704_0
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1704_0`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```go
Lines 151-191 of the vulnerable file.

	for _, kv := range kvs {
		for _, v := range kv.values {
			v = headerNewlineToSpace.Replace(v)
			v = textproto.TrimString(v)
			for _, s := range []string{kv.key, ": ", v, "\r\n"} {
				if _, err := ws.WriteString(s); err != nil {
					return err
				}
			}
		}
	}
	headerSorterPool.Put(sorter)
	return nil
}

// CanonicalHeaderKey returns the canonical format of the
// header key s.  The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase.  For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
func CanonicalHeaderKey(s string) string { return textproto.CanonicalMIMEHeaderKey(s) }

// hasToken reports whether token appears with v, ASCII
// case-insensitive, with space or comma boundaries.
// token must be all lowercase.
// v may contain mixed cased.
func hasToken(v, token string) bool {
	if len(token) > len(v) || token == "" {
		return false
	}
	if v == token {
		return true
	}
	for sp := 0; sp <= len(v)-len(token); sp++ {
		// Check that first character is good.
		// The token is ASCII, so checking only a single byte
		// is sufficient.  We skip this potential starting
		// position if both the first byte and its potential
		// ASCII uppercase equivalent (b|0x20) don't match.
		// False positives ('^' => '~') are caught by EqualFold.
		if b := v[sp]; b != token[0] && b|0x20 != token[0] {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -168,6 +168,8 @@
 // letter and any letter following a hyphen to upper case;
 // the rest are converted to lowercase.  For example, the
 // canonical key for "accept-encoding" is "Accept-Encoding".
+// If s contains a space or invalid header field bytes, it is
+// returned without modifications.
 func CanonicalHeaderKey(s string) string { return textproto.CanonicalMIMEHeaderKey(s) }
 
 // hasToken reports whether token appears with v, ASCII
```
