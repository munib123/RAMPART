# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in go
**Pair ID:** 855_4
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `855_4`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```go
Lines 2-42 of the vulnerable file.

 * Copyright (c) Facebook, Inc. and its affiliates.
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

package thrift

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
)

// Default to using the shared http client. Library users are
// free to change this global client or specify one through
// HTTPClientOptions.
var DefaultHTTPClient *http.Client = http.DefaultClient

type HTTPClient struct {
	client             *http.Client
	response           *http.Response
	url                *url.URL
	requestBuffer      *bytes.Buffer
	header             http.Header
	nsecConnectTimeout int64
	nsecReadTimeout    int64
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,7 +19,6 @@
 import (
 	"bytes"
 	"io"
-	"io/ioutil"
 	"net/http"
 	"net/url"
 	"strconv"
@@ -35,6 +34,7 @@
 	response           *http.Response
 	url                *url.URL
 	requestBuffer      *bytes.Buffer
+	responseBuffer     bytes.Buffer
 	header             http.Header
 	nsecConnectTimeout int64
 	nsecReadTimeout    int64
@@ -164,20 +164,9 @@
 }
 
 func (p *HTTPClient) closeResponse() error {
-	var err error
-	if p.response != nil && p.response.Body != nil {
-		// The docs specify that if keepalive is enabled and the response body is not
-		// read to completion the connection will never be returned to the pool and
-		// reused. Errors are being ignored here because if the connection is invalid
-		// and this fails for some reason, the Close() method will do any remaining
-		// cleanup.
-		io.Copy(ioutil.Discard, p.response.Body)
-
-		err = p.response.Body.Close()
-	}
-
 	p.response = nil
-	return err
+	p.responseBuffer.Reset()
+	return nil
 }
 
 func (p *HTTPClient) Close() error {
@@ -192,7 +181,7 @@
 	if p.response == nil {
 		return 0, NewTransportException(NOT_OPEN, "Response buffer is empty, no request.")
 	}
-	n, err := p.response.Body.Read(buf)
+	n, err := p.responseBuffer.Read(buf)
 	if n > 0 && (err == nil || err == io.EOF) {
 		return n, nil
 	}
@@ -200,7 +189,7 @@
 }
 
 func (p *HTTPClient) ReadByte() (c byte, err error) {
-	return readByte(p.response.Body)
+	return readByte(&p.responseBuffer)
 }
 
 func (p *HTTPClient) Write(buf []byte) (int, error) {
@@ -230,6 +219,9 @@
 	if err != nil {
 		return NewTransportExceptionFromError(err)
 	}
+
+	defer response.Body.Close()
+
 	if response.StatusCode != http.StatusOK {
 		// Close the response to avoid leaking file descriptors. closeResponse does
 		// more than just call Close(), so temporarily assign it and reuse the logic.
@@ -239,15 +231,16 @@
 		// TODO(pomack) log bad response
 		return NewTransportException(UNKNOWN_TRANSPORT_EXCEPTION, "HTTP Response code: "+strconv.Itoa(response.StatusCode))
 	}
+
+	_, err = io.Copy(&p.responseBuffer, response.Body)
+	if err != nil {
+		return NewTransportExceptionFromError(err)
+	}
+
 	p.response = response
 	return nil
 }
 
 func (p *HTTPClient) RemainingBytes() (num_bytes uint64) {
-	len := p.response.ContentLength
-	if len >= 0 {
-		return uint64(len)
-	}
-
-	return UnknownRemaining // the truth is, we just don't know unless framed is used
-}
+	return uint64(p.responseBuffer.Len())
+}
```
