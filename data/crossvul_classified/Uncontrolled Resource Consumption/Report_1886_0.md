# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 1886_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1886_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 170-211 of the vulnerable file.

    'inactivecaption': (0.8, 0.8, 0.8, 1),
    'inactivecaptiontext': (0.2, 0.2, 0.2, 1),
    'infobackground': (0.8, 0.8, 0.8, 1),
    'infotext': (0, 0, 0, 1),
    'menu': (0.8, 0.8, 0.8, 1),
    'menutext': (0.2, 0.2, 0.2, 1),
    'scrollbar': (0.8, 0.8, 0.8, 1),
    'threeddarkshadow': (0.2, 0.2, 0.2, 1),
    'threedface': (0.8, 0.8, 0.8, 1),
    'threedhighlight': (1, 1, 1, 1),
    'threedlightshadow': (0.2, 0.2, 0.2, 1),
    'threedshadow': (0.2, 0.2, 0.2, 1),
    'window': (0.8, 0.8, 0.8, 1),
    'windowframe': (0.8, 0.8, 0.8, 1),
    'windowtext': (0, 0, 0, 1),

    'none': (0, 0, 0, 0),
    'transparent': (0, 0, 0, 0),
}

RGBA = re.compile(r'rgba\([ \n\r\t]*(.+?)[ \n\r\t]*\)')
RGB = re.compile(r'rgb\([ \n\r\t]*(.+?)[ \n\r\t]*\)')
HEX_RRGGBB = re.compile('#[0-9a-f]{6}')
HEX_RGB = re.compile('#[0-9a-f]{3}')


def color(string, opacity=1):
    """Replace ``string`` representing a color by a RGBA tuple.

    See http://www.w3.org/TR/SVG/types.html#DataTypeColor

    """
    if not string:
        return (0, 0, 0, 0)

    string = string.strip().lower()

    if string in COLORS:
        r, g, b, a = COLORS[string]
        return (r, g, b, a * opacity)

    match = RGBA.search(string)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -187,8 +187,8 @@
     'transparent': (0, 0, 0, 0),
 }
 
-RGBA = re.compile(r'rgba\([ \n\r\t]*(.+?)[ \n\r\t]*\)')
-RGB = re.compile(r'rgb\([ \n\r\t]*(.+?)[ \n\r\t]*\)')
+RGBA = re.compile(r'rgba\((.+?)\)')
+RGB = re.compile(r'rgb\((.+?)\)')
 HEX_RRGGBB = re.compile('#[0-9a-f]{6}')
 HEX_RGB = re.compile('#[0-9a-f]{3}')
 
@@ -212,14 +212,14 @@
     if match:
         r, g, b, a = tuple(
             float(i.strip(' %')) / 100 if '%' in i else float(i) / 255
-            for i in match.group(1).split(','))
+            for i in match.group(1).strip().split(','))
         return (r, g, b, a * 255 * opacity)
 
     match = RGB.search(string)
     if match:
         r, g, b = tuple(
             float(i.strip(' %')) / 100 if '%' in i else float(i) / 255
-            for i in match.group(1).split(','))
+            for i in match.group(1).strip().split(','))
         return (r, g, b, opacity)
 
     match = HEX_RRGGBB.search(string)
```
