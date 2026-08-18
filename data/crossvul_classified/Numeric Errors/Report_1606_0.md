# CrossVul Fix Pair: Numeric Errors in cpp
**Pair ID:** 1606_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1606_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```cpp
Lines 873-913 of the vulnerable file.

	  cblack[c] += (cblack[4+c]++,pixel[r*raw_width+col]);
      }
    }
  }
  free (pixel);
  FORC(2) free (huff[c]);
  FORC4 if (cblack[4+c]) cblack[c] /= cblack[4+c];
}

/*
   Not a full implementation of Lossless JPEG, just
   enough to decode Canon, Kodak and Adobe DNG images.
 */
struct jhead {
  int bits, high, wide, clrs, sraw, psv, restart, vpred[6];
  ushort *huff[6], *free[4], *row;
};

int CLASS ljpeg_start (struct jhead *jh, int info_only)
{
  int c, tag, len;
  uchar data[0x10000];
  const uchar *dp;

  memset (jh, 0, sizeof *jh);
  jh->restart = INT_MAX;
  fread (data, 2, 1, ifp);
  if (data[1] != 0xd8) return 0;
  do {
    fread (data, 2, 2, ifp);
    tag =  data[0] << 8 | data[1];
    len = (data[2] << 8 | data[3]) - 2;
    if (tag <= 0xff00) return 0;
    fread (data, 1, len, ifp);
    switch (tag) {
      case 0xffc3:
	jh->sraw = ((data[7] >> 4) * (data[7] & 15) - 1) & 3;
      case 0xffc0:
	jh->bits = data[0];
	jh->high = data[1] << 8 | data[2];
	jh->wide = data[3] << 8 | data[4];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -890,7 +890,8 @@
 
 int CLASS ljpeg_start (struct jhead *jh, int info_only)
 {
-  int c, tag, len;
+  int c, tag;
+  ushort len;
   uchar data[0x10000];
   const uchar *dp;
 
```
