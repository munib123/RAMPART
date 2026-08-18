# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 2156_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2156_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 162-202 of the vulnerable file.

        (16, 16, 1): [
            (b'icp4', read_png_or_jpeg2000),
            (b'is32', read_32),
            (b's8mk', read_mk),
        ],
    }

    def __init__(self, fobj):
        """
        fobj is a file-like object as an icns resource
        """
        # signature : (start, length)
        self.dct = dct = {}
        self.fobj = fobj
        sig, filesize = nextheader(fobj)
        if sig != b'icns':
            raise SyntaxError('not an icns file')
        i = HEADERSIZE
        while i < filesize:
            sig, blocksize = nextheader(fobj)
            i += HEADERSIZE
            blocksize -= HEADERSIZE
            dct[sig] = (i, blocksize)
            fobj.seek(blocksize, 1)
            i += blocksize

    def itersizes(self):
        sizes = []
        for size, fmts in self.SIZES.items():
            for (fmt, reader) in fmts:
                if fmt in self.dct:
                    sizes.append(size)
                    break
        return sizes

    def bestsize(self):
        sizes = self.itersizes()
        if not sizes:
            raise SyntaxError("No 32bit icon resources found")
        return max(sizes)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -179,6 +179,8 @@
         i = HEADERSIZE
         while i < filesize:
             sig, blocksize = nextheader(fobj)
+            if blocksize <= 0:
+                raise SyntaxError('invalid block header')
             i += HEADERSIZE
             blocksize -= HEADERSIZE
             dct[sig] = (i, blocksize)
```
