# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 5399_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5399_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 74-114 of the vulnerable file.

                "Can not derive keys larger than {0} octets.".format(
                    max_length
                ))

        self._length = length

        if not (info is None or isinstance(info, bytes)):
            raise TypeError("info must be bytes.")

        if info is None:
            info = b""

        self._info = info

        self._used = False

    def _expand(self, key_material):
        output = [b""]
        counter = 1

        while (self._algorithm.digest_size // 8) * len(output) < self._length:
            h = hmac.HMAC(key_material, self._algorithm, backend=self._backend)
            h.update(output[-1])
            h.update(self._info)
            h.update(six.int2byte(counter))
            output.append(h.finalize())
            counter += 1

        return b"".join(output)[:self._length]

    def derive(self, key_material):
        if not isinstance(key_material, bytes):
            raise TypeError("key_material must be bytes.")

        if self._used:
            raise AlreadyFinalized

        self._used = True
        return self._expand(key_material)

    def verify(self, key_material, expected_key):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,7 +91,7 @@
         output = [b""]
         counter = 1
 
-        while (self._algorithm.digest_size // 8) * len(output) < self._length:
+        while self._algorithm.digest_size * (len(output) - 1) < self._length:
             h = hmac.HMAC(key_material, self._algorithm, backend=self._backend)
             h.update(output[-1])
             h.update(self._info)
```
