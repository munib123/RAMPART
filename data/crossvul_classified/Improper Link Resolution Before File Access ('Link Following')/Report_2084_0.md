# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in python
**Pair ID:** 2084_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2084_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```python
Lines 50-90 of the vulnerable file.

    else:
        gs_windows_binary = False

def Ghostscript(tile, size, fp, scale=1):
    """Render an image using Ghostscript"""

    # Unpack decoder tile
    decoder, tile, offset, data = tile[0]
    length, bbox = data

    #Hack to support hi-res rendering
    scale = int(scale) or 1
    orig_size = size
    orig_bbox = bbox
    size = (size[0] * scale, size[1] * scale)
    bbox = [bbox[0], bbox[1], bbox[2] * scale, bbox[3] * scale]
    #print("Ghostscript", scale, size, orig_size, bbox, orig_bbox)

    import tempfile, os, subprocess

    file = tempfile.mktemp()

    # Build ghostscript command
    command = ["gs",
               "-q",                    # quite mode
               "-g%dx%d" % size,        # set output geometry (pixels)
               "-r%d" % (72*scale),     # set input DPI (dots per inch)
               "-dNOPAUSE -dSAFER",     # don't pause between pages, safe mode
               "-sDEVICE=ppmraw",       # ppm driver
               "-sOutputFile=%s" % file,# output file
            ]

    if gs_windows_binary is not None:
        if gs_windows_binary is False:
            raise WindowsError('Unable to locate Ghostscript on paths')
        command[0] = gs_windows_binary

    # push data through ghostscript
    try:
        gs = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        # adjust for image origin
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,7 +67,8 @@
 
     import tempfile, os, subprocess
 
-    file = tempfile.mktemp()
+    out_fd, file = tempfile.mkstemp()
+    os.close(out_fd)
 
     # Build ghostscript command
     command = ["gs",
```
