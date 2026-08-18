# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 3934_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3934_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 58-98 of the vulnerable file.

    """

    def __init__(self, sock):
        self._buf = b""
        self._end = False
        self._newline = b"\r\n"
        self._sock = sock
        if isinstance(sock, bytes):
            self._sock = None
            self._buf = sock

    def _fill(self, target=1, more=None, untilend=False):
        if more:
            target = len(self._buf) + more
        while untilend or (len(self._buf) < target):
            # crutch to enable HttpRequest.from_bytes
            if self._sock is None:
                chunk = b""
            else:
                chunk = self._sock.recv(8 << 10)
            # print('!!! recv', chunk)
            if not chunk:
                self._end = True
                if untilend:
                    return
                else:
                    raise EOFError
            self._buf += chunk

    def peek(self, size):
        self._fill(target=size)
        return self._buf[:size]

    def read(self, size):
        self._fill(target=size)
        chunk, self._buf = self._buf[:size], self._buf[size:]
        return chunk

    def readall(self):
        self._fill(untilend=True)
        chunk, self._buf = self._buf, b""
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,7 +75,7 @@
                 chunk = b""
             else:
                 chunk = self._sock.recv(8 << 10)
-            # print('!!! recv', chunk)
+            # print("!!! recv", chunk)
             if not chunk:
                 self._end = True
                 if untilend:
```
