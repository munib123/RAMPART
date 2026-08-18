# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in python
**Pair ID:** 2084_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2084_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```python
Lines 478-518 of the vulnerable file.

        if im.mode == "P" and not new.palette:
            from PIL import ImagePalette
            new.palette = ImagePalette.ImagePalette()
        try:
            new.info = self.info.copy()
        except AttributeError:
            # fallback (pre-1.5.2)
            new.info = {}
            for k, v in self.info:
                new.info[k] = v
        return new

    _makeself = _new # compatibility

    def _copy(self):
        self.load()
        self.im = self.im.copy()
        self.readonly = 0

    def _dump(self, file=None, format=None):
        import tempfile
        if not file:
            file = tempfile.mktemp()
        self.load()
        if not format or format == "PPM":
            self.im.save_ppm(file)
        else:
            file = file + "." + format
            self.save(file, format)
        return file

    def __repr__(self):
        return "<%s.%s image mode=%s size=%dx%d at 0x%X>" % (
            self.__class__.__module__, self.__class__.__name__,
            self.mode, self.size[0], self.size[1],
            id(self)
            )

    def __getattr__(self, name):
        if name == "__array_interface__":
            # numpy array interface support
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -495,14 +495,17 @@
         self.readonly = 0
 
     def _dump(self, file=None, format=None):
-        import tempfile
+        import tempfile, os
         if not file:
-            file = tempfile.mktemp()
+            f, file = tempfile.mkstemp(format or '')
+            os.close(f)
+            
         self.load()
         if not format or format == "PPM":
             self.im.save_ppm(file)
         else:
-            file = file + "." + format
+            if file.endswith(format):
+                file = file + "." + format
             self.save(file, format)
         return file
 
```
