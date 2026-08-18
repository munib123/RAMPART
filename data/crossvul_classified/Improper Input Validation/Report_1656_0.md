# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 1656_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1656_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 44-84 of the vulnerable file.

        headers = list(filter(lambda h: h[0] != 'Content-Length', headers))

        if 'Content-Type' not in dict(headers):
            headers.append(('Content-Type', 'text/plain; charset=utf-8'))

        if sys.version_info.major == 3 and isinstance(msg, str):
            msg = bytes(msg, "utf-8")

        headers.append(('Content-Length', str(len(msg))))

        super(HTTPException, self).__init__(code, msg, headers)
        self.code = code
        self.message = msg
        self.headers = headers

    def __str__(self):
        return "%d %s" % (self.code, httplib.responses[self.code])


class Application:
    SOCKTYPES = {
        "tcp": socket.SOCK_STREAM,
        "udp": socket.SOCK_DGRAM,
    }

    def __init__(self):
        self.__resolver = MetaResolver()

    def __await_reply(self, pr, rsocks, wsocks, timeout):
        extra = 0
        read_buffers = {}
        while (timeout + extra) > time.time():
            if not wsocks and not rsocks:
                break

            r, w, x = select.select(rsocks, wsocks, rsocks + wsocks,
                                    (timeout + extra) - time.time())
            for sock in x:
                sock.close()
                try:
                    rsocks.remove(sock)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,6 +61,7 @@
 
 
 class Application:
+    MAX_LENGTH = 128 * 1024
     SOCKTYPES = {
         "tcp": socket.SOCK_STREAM,
         "udp": socket.SOCK_DGRAM,
@@ -180,7 +181,11 @@
             try:
                 length = int(env["CONTENT_LENGTH"])
             except AttributeError:
-                length = -1
+                raise HTTPException(411, "Length required.")
+            if length < 0:
+                raise HTTPException(411, "Length required.")
+            if length > self.MAX_LENGTH:
+                raise HTTPException(413, "Request entity too large.")
             try:
                 pr = codec.decode(env["wsgi.input"].read(length))
             except codec.ParsingError as e:
```
