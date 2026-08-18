# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in python
**Pair ID:** 2084_3
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2084_3`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```python
Lines 327-368 of the vulnerable file.


        if size:
            scale = max(self.size[0] // size[0], self.size[1] // size[1])
            for s in [8, 4, 2, 1]:
                if scale >= s:
                    break
            e = e[0], e[1], (e[2]-e[0]+s-1)//s+e[0], (e[3]-e[1]+s-1)//s+e[1]
            self.size = ((self.size[0]+s-1)//s, (self.size[1]+s-1)//s)
            scale = s

        self.tile = [(d, e, o, a)]
        self.decoderconfig = (scale, 1)

        return self

    def load_djpeg(self):

        # ALTERNATIVE: handle JPEGs via the IJG command line utilities

        import tempfile, os
        file = tempfile.mktemp()
        os.system("djpeg %s >%s" % (self.filename, file))

        try:
            self.im = Image.core.open_ppm(file)
        finally:
            try: os.unlink(file)
            except: pass

        self.mode = self.im.mode
        self.size = self.im.size

        self.tile = []

    def _getexif(self):
        return _getexif(self)


def _getexif(self):
    # Extract EXIF information.  This method is highly experimental,
    # and is likely to be replaced with something better in a future
    # version.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -344,13 +344,17 @@
         # ALTERNATIVE: handle JPEGs via the IJG command line utilities
 
         import tempfile, os
-        file = tempfile.mktemp()
-        os.system("djpeg %s >%s" % (self.filename, file))
+        f, path = tempfile.mkstemp()
+        os.close(f)
+        if os.path.exists(self.filename):
+            os.system("djpeg '%s' >'%s'" % (self.filename, path))
+        else:
+            raise ValueError("Invalid Filename")
 
         try:
-            self.im = Image.core.open_ppm(file)
+            self.im = Image.core.open_ppm(path)
         finally:
-            try: os.unlink(file)
+            try: os.unlink(path)
             except: pass
 
         self.mode = self.im.mode
```
