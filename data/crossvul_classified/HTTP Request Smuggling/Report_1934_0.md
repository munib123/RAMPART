# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in rust
**Pair ID:** 1934_0
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1934_0`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```rust
Lines 196-236 of the vulnerable file.

        headers.reserve(headers_len);

        for header in &headers_indices[..headers_len] {
            let name = header_name!(&slice[header.name.0..header.name.1]);
            let value = header_value!(slice.slice(header.value.0..header.value.1));

            match name {
                header::TRANSFER_ENCODING => {
                    // https://tools.ietf.org/html/rfc7230#section-3.3.3
                    // If Transfer-Encoding header is present, and 'chunked' is
                    // not the final encoding, and this is a Request, then it is
                    // malformed. A server should respond with 400 Bad Request.
                    if !is_http_11 {
                        debug!("HTTP/1.0 cannot have Transfer-Encoding header");
                        return Err(Parse::Header);
                    }
                    is_te = true;
                    if headers::is_chunked_(&value) {
                        is_te_chunked = true;
                        decoder = DecodedLength::CHUNKED;
                    }
                }
                header::CONTENT_LENGTH => {
                    if is_te {
                        continue;
                    }
                    let len = value
                        .to_str()
                        .map_err(|_| Parse::Header)
                        .and_then(|s| s.parse().map_err(|_| Parse::Header))?;
                    if let Some(prev) = con_len {
                        if prev != len {
                            debug!(
                                "multiple Content-Length headers with different values: [{}, {}]",
                                prev, len,
                            );
                            return Err(Parse::Header);
                        }
                        // we don't need to append this secondary length
                        continue;
                    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -213,6 +213,8 @@
                     if headers::is_chunked_(&value) {
                         is_te_chunked = true;
                         decoder = DecodedLength::CHUNKED;
+                    } else {
+                        is_te_chunked = false;
                     }
                 }
                 header::CONTENT_LENGTH => {
@@ -1444,6 +1446,16 @@
             "transfer-encoding doesn't end in chunked",
         );
 
+        parse_err(
+            "\
+             POST / HTTP/1.1\r\n\
+             transfer-encoding: chunked\r\n\
+             transfer-encoding: afterlol\r\n\
+             \r\n\
+             ",
+            "transfer-encoding multiple lines doesn't end in chunked",
+        );
+
         // http/1.0
 
         assert_eq!(
```
