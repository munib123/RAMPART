# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in go
**Pair ID:** 1704_1
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1704_1`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```go
Lines 530-570 of the vulnerable file.

	peek, _ := r.R.Peek(s)
	for len(peek) > 0 {
		i := bytes.IndexByte(peek, '\n')
		if i < 3 {
			// Not present (-1) or found within the next few bytes,
			// implying we're at the end ("\r\n\r\n" or "\n\n")
			return
		}
		n++
		peek = peek[i+1:]
	}
	return
}

// CanonicalMIMEHeaderKey returns the canonical format of the
// MIME header key s.  The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase.  For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
// MIME header keys are assumed to be ASCII only.
func CanonicalMIMEHeaderKey(s string) string {
	// Quick check for canonical encoding.
	upper := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if upper && 'a' <= c && c <= 'z' {
			return canonicalMIMEHeaderKey([]byte(s))
		}
		if !upper && 'A' <= c && c <= 'Z' {
			return canonicalMIMEHeaderKey([]byte(s))
		}
		upper = c == '-'
	}
	return s
}

const toLower = 'a' - 'A'

// canonicalMIMEHeaderKey is like CanonicalMIMEHeaderKey but is
// allowed to mutate the provided byte slice before returning the
// string.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -547,11 +547,16 @@
 // the rest are converted to lowercase.  For example, the
 // canonical key for "accept-encoding" is "Accept-Encoding".
 // MIME header keys are assumed to be ASCII only.
+// If s contains a space or invalid header field bytes, it is
+// returned without modifications.
 func CanonicalMIMEHeaderKey(s string) string {
 	// Quick check for canonical encoding.
 	upper := true
 	for i := 0; i < len(s); i++ {
 		c := s[i]
+		if !validHeaderFieldByte(c) {
+			return s
+		}
 		if upper && 'a' <= c && c <= 'z' {
 			return canonicalMIMEHeaderKey([]byte(s))
 		}
@@ -564,20 +569,45 @@
 }
 
 const toLower = 'a' - 'A'
+
+// validHeaderFieldByte reports whether b is a valid byte in a header
+// field key. This is actually stricter than RFC 7230, which says:
+//   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
+//           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
+//   token = 1*tchar
+// TODO: revisit in Go 1.6+ and possibly expand this. But note that many
+// servers have historically dropped '_' to prevent ambiguities when mapping
+// to CGI environment variables.
+func validHeaderFieldByte(b byte) bool {
+	return ('A' <= b && b <= 'Z') ||
+		('a' <= b && b <= 'z') ||
+		('0' <= b && b <= '9') ||
+		b == '-'
+}
 
 // canonicalMIMEHeaderKey is like CanonicalMIMEHeaderKey but is
 // allowed to mutate the provided byte slice before returning the
 // string.
+//
+// For invalid inputs (if a contains spaces or non-token bytes), a
+// is unchanged and a string copy is returned.
 func canonicalMIMEHeaderKey(a []byte) string {
+	// See if a looks like a header key. If not, return it unchanged.
+	for _, c := range a {
+		if validHeaderFieldByte(c) {
+			continue
+		}
+		// Don't canonicalize.
+		return string(a)
+	}
+
 	upper := true
 	for i, c := range a {
 		// Canonicalize: first letter upper case
 		// and upper case after each dash.
 		// (Host, User-Agent, If-Modified-Since).
 		// MIME headers are ASCII only, so no Unicode issues.
-		if c == ' ' {
-			c = '-'
-		} else if upper && 'a' <= c && c <= 'z' {
+		if upper && 'a' <= c && c <= 'z' {
 			c -= toLower
 		} else if !upper && 'A' <= c && c <= 'Z' {
 			c += toLower
```
