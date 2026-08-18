# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in python
**Pair ID:** 1123_0
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1123_0`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```python
Lines 237-277 of the vulnerable file.


        if version == "1.1":
            # since the server buffers data from chunked transfers and clients
            # never need to deal with chunked requests, downstream clients
            # should not see the HTTP_TRANSFER_ENCODING header; we pop it
            # here
            te = headers.pop("TRANSFER_ENCODING", "")
            if te.lower() == "chunked":
                self.chunked = True
                buf = OverflowableBuffer(self.adj.inbuf_overflow)
                self.body_rcv = ChunkedReceiver(buf)
            expect = headers.get("EXPECT", "").lower()
            self.expect_continue = expect == "100-continue"
            if connection.lower() == "close":
                self.connection_close = True

        if not self.chunked:
            try:
                cl = int(headers.get("CONTENT_LENGTH", 0))
            except ValueError:
                cl = 0
            self.content_length = cl
            if cl > 0:
                buf = OverflowableBuffer(self.adj.inbuf_overflow)
                self.body_rcv = FixedStreamReceiver(cl, buf)

    def get_body_stream(self):
        body_rcv = self.body_rcv
        if body_rcv is not None:
            return body_rcv.getfile()
        else:
            return BytesIO()

    def close(self):
        body_rcv = self.body_rcv
        if body_rcv is not None:
            body_rcv.getbuf().close()


def split_uri(uri):
    # urlsplit handles byte input by returning bytes on py3, so
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -254,7 +254,8 @@
             try:
                 cl = int(headers.get("CONTENT_LENGTH", 0))
             except ValueError:
-                cl = 0
+                raise ParsingError("Content-Length is invalid")
+
             self.content_length = cl
             if cl > 0:
                 buf = OverflowableBuffer(self.adj.inbuf_overflow)
```
