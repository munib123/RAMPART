# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in go
**Pair ID:** 1705_1
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1705_1`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```go
Lines 131-171 of the vulnerable file.


func noBodyExpected(requestMethod string) bool {
	return requestMethod == "HEAD"
}

func (t *transferWriter) shouldSendContentLength() bool {
	if chunked(t.TransferEncoding) {
		return false
	}
	if t.ContentLength > 0 {
		return true
	}
	if t.ContentLength < 0 {
		return false
	}
	// Many servers expect a Content-Length for these methods
	if t.Method == "POST" || t.Method == "PUT" {
		return true
	}
	if t.ContentLength == 0 && isIdentity(t.TransferEncoding) {
		return true
	}

	return false
}

func (t *transferWriter) WriteHeader(w io.Writer) error {
	if t.Close {
		if _, err := io.WriteString(w, "Connection: close\r\n"); err != nil {
			return err
		}
	}

	// Write Content-Length and/or Transfer-Encoding whose values are a
	// function of the sanitized field triple (Body, ContentLength,
	// TransferEncoding)
	if t.shouldSendContentLength() {
		if _, err := io.WriteString(w, "Content-Length: "); err != nil {
			return err
		}
		if _, err := io.WriteString(w, strconv.FormatInt(t.ContentLength, 10)+"\r\n"); err != nil {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -148,6 +148,9 @@
 		return true
 	}
 	if t.ContentLength == 0 && isIdentity(t.TransferEncoding) {
+		if t.Method == "GET" || t.Method == "HEAD" {
+			return false
+		}
 		return true
 	}
 
@@ -317,6 +320,7 @@
 		}
 	case *Request:
 		t.Header = rr.Header
+		t.RequestMethod = rr.Method
 		t.ProtoMajor = rr.ProtoMajor
 		t.ProtoMinor = rr.ProtoMinor
 		// Transfer semantics for Requests are exactly like those for
@@ -333,7 +337,7 @@
 	}
 
 	// Transfer encoding, content length
-	t.TransferEncoding, err = fixTransferEncoding(t.RequestMethod, t.Header)
+	t.TransferEncoding, err = fixTransferEncoding(isResponse, t.RequestMethod, t.Header)
 	if err != nil {
 		return err
 	}
@@ -421,12 +425,12 @@
 func isIdentity(te []string) bool { return len(te) == 1 && te[0] == "identity" }
 
 // Sanitize transfer encoding
-func fixTransferEncoding(requestMethod string, header Header) ([]string, error) {
+func fixTransferEncoding(isResponse bool, requestMethod string, header Header) ([]string, error) {
 	raw, present := header["Transfer-Encoding"]
 	if !present {
 		return nil, nil
 	}
-
+	isRequest := !isResponse
 	delete(header, "Transfer-Encoding")
 
 	encodings := strings.Split(raw[0], ",")
@@ -451,10 +455,15 @@
 		return nil, &badStringError{"too many transfer encodings", strings.Join(te, ",")}
 	}
 	if len(te) > 0 {
-		// Chunked encoding trumps Content-Length. See RFC 2616
-		// Section 4.4. Currently len(te) > 0 implies chunked
-		// encoding.
-		delete(header, "Content-Length")
+		// RFC 7230 3.3.2 says "A sender MUST NOT send a
+		// Content-Length header field in any message that
+		// contains a Transfer-Encoding header field."
+		if len(header["Content-Length"]) > 0 {
+			if isRequest {
+				return nil, errors.New("http: invalid Content-Length with Transfer-Encoding")
+			}
+			delete(header, "Content-Length")
+		}
 		return te, nil
 	}
 
@@ -465,9 +474,17 @@
 // function is not a method, because ultimately it should be shared by
 // ReadResponse and ReadRequest.
 func fixLength(isResponse bool, status int, requestMethod string, header Header, te []string) (int64, error) {
-
+	contentLens := header["Content-Length"]
+	isRequest := !isResponse
 	// Logic based on response type or status
 	if noBodyExpected(requestMethod) {
+		// For HTTP requests, as part of hardening against request
+		// smuggling (RFC 7230), don't allow a Content-Length header for
+		// methods which don't permit bodies. As an exception, allow
+		// exactly one Content-Length header if its value is "0".
+		if isRequest && len(contentLens) > 0 && !(len(contentLens) == 1 && contentLens[0] == "0") {
+			return 0, fmt.Errorf("http: method cannot contain a Content-Length; got %q", contentLens)
+		}
 		return 0, nil
 	}
 	if status/100 == 1 {
@@ -478,13 +495,21 @@
 		return 0, nil
 	}
 
+	if len(contentLens) > 1 {
+		// harden against HTTP request smuggling. See RFC 7230.
+		return 0, errors.New("http: message cannot contain multiple Content-Length headers")
+	}
+
 	// Logic based on Transfer-Encoding
 	if chunked(te) {
 		return -1, nil
 	}
 
 	// Logic based on Content-Length
-	cl := strings.TrimSpace(header.get("Content-Length"))
+	var cl string
+	if len(contentLens) == 1 {
+		cl = strings.TrimSpace(contentLens[0])
+	}
 	if cl != "" {
 		n, err := parseContentLength(cl)
 		if err != nil {
@@ -495,11 +520,14 @@
 		header.Del("Content-Length")
 	}
 
-	if !isResponse && requestMethod == "GET" {
-		// RFC 2616 doesn't explicitly permit nor forbid an
+	if !isResponse {
+		// RFC 2616 neither explicitly permits nor forbids an
 		// entity-body on a GET request so we permit one if
 		// declared, but we default to 0 here (not -1 below)
 		// if there's no mention of a body.
+		// Likewise, all other request methods are assumed to have
+		// no body if neither Transfer-Encoding chunked nor a
+		// Content-Length are set.
 		return 0, nil
 	}
 
```
