# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3226_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3226_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 302-342 of the vulnerable file.

  }
}

void CLASS foveon_huff (ushort *huff)
{
  int i, j, clen, code;

  huff[0] = 8;
  for (i=0; i < 13; i++) {
    clen = getc(ifp);
    code = getc(ifp);
    for (j=0; j < 256 >> clen; )
      huff[code+ ++j] = clen << 8 | i;
  }
  get2();
}

void CLASS foveon_dp_load_raw()
{
  unsigned c, roff[4], row, col, diff;
  ushort huff[512], vpred[2][2], hpred[2];

  fseek (ifp, 8, SEEK_CUR);
  foveon_huff (huff);
  roff[0] = 48;
  FORC3 roff[c+1] = -(-(roff[c] + get4()) & -16);
  FORC3 {
    fseek (ifp, data_offset+roff[c], SEEK_SET);
    getbits(-1);
    vpred[0][0] = vpred[0][1] = vpred[1][0] = vpred[1][1] = 512;
    for (row=0; row < height; row++) {
#ifdef LIBRAW_LIBRARY_BUILD
    checkCancel();
#endif
      for (col=0; col < width; col++) {
	diff = ljpeg_diff(huff);
	if (col < 2) hpred[col] = vpred[row & 1][col] += diff;
	else hpred[col & 1] += diff;
	image[row*width+col][c] = hpred[col & 1];
      }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -319,7 +319,7 @@
 void CLASS foveon_dp_load_raw()
 {
   unsigned c, roff[4], row, col, diff;
-  ushort huff[512], vpred[2][2], hpred[2];
+  ushort huff[1024], vpred[2][2], hpred[2];
 
   fseek (ifp, 8, SEEK_CUR);
   foveon_huff (huff);
@@ -346,12 +346,16 @@
 void CLASS foveon_load_camf()
 {
   unsigned type, wide, high, i, j, row, col, diff;
-  ushort huff[258], vpred[2][2] = {{512,512},{512,512}}, hpred[2];
+  ushort huff[1024], vpred[2][2] = {{512,512},{512,512}}, hpred[2];
 
   fseek (ifp, meta_offset, SEEK_SET);
   type = get4();  get4();  get4();
   wide = get4();
   high = get4();
+#ifdef LIBRAW_LIBRARY_BUILD
+  if(wide>32767 || high > 32767 || wide*high > 20000000)
+     throw LIBRAW_EXCEPTION_IO_CORRUPT;
+#endif
   if (type == 2) {
     fread (meta_data, 1, meta_length, ifp);
     for (i=0; i < meta_length; i++) {
```
