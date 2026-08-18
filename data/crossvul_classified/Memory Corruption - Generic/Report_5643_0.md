# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 5643_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5643_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 2319-2360 of the vulnerable file.

}


int LibRaw::subtract_black()
{
	CHECK_ORDER_LOW(LIBRAW_PROGRESS_RAW2_IMAGE);

	try {
    if(!is_phaseone_compressed() && (C.cblack[0] || C.cblack[1] || C.cblack[2] || C.cblack[3]))
        {
#define BAYERC(row,col,c) imgdata.image[((row) >> IO.shrink)*S.iwidth + ((col) >> IO.shrink)][c] 
            int cblk[4],i;
            for(i=0;i<4;i++)
                cblk[i] = C.cblack[i];

            int size = S.iheight * S.iwidth;
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define LIM(x,min,max) MAX(min,MIN(x,max))
#define CLIP(x) LIM(x,0,65535)

            for(i=0; i< size*4; i++)
              {
                int val = imgdata.image[0][i];
                val -= cblk[i & 3];
                imgdata.image[0][i] = CLIP(val);
                if(C.data_maximum < val) C.data_maximum = val;
              }
#undef MIN
#undef MAX
#undef LIM
#undef CLIP
            C.maximum -= C.black;
            ZERO(C.cblack);
            C.black = 0;
#undef BAYERC
        }
    else
        {
          // Nothing to Do, maximum is already calculated, black level is 0, so no change
          // only calculate channel maximum;
          int idx;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2336,14 +2336,15 @@
 #define MAX(a,b) ((a) > (b) ? (a) : (b))
 #define LIM(x,min,max) MAX(min,MIN(x,max))
 #define CLIP(x) LIM(x,0,65535)
-
-            for(i=0; i< size*4; i++)
+			int dmax = 0;
+			for(i=0; i< size*4; i++)
               {
                 int val = imgdata.image[0][i];
                 val -= cblk[i & 3];
                 imgdata.image[0][i] = CLIP(val);
-                if(C.data_maximum < val) C.data_maximum = val;
+                if(dmax < val) dmax = val;
               }
+			C.data_maximum = dmax & 0xffff;
 #undef MIN
 #undef MAX
 #undef LIM
@@ -2359,9 +2360,10 @@
           // only calculate channel maximum;
           int idx;
           ushort *p = (ushort*)imgdata.image;
-          C.data_maximum = 0;
+		  int dmax = 0;
           for(idx=0;idx<S.iheight*S.iwidth*4;idx++)
-            if(C.data_maximum < p[idx]) C.data_maximum = p[idx];
+            if(dmax < p[idx]) dmax = p[idx];
+		  C.data_maximum = dmax;
         }
 		return 0;
 	}
@@ -2421,8 +2423,10 @@
             imgdata.image[i][3] = lut[imgdata.image[i][3]];
         }
 
-    C.data_maximum = lut[C.data_maximum];
-    C.maximum = lut[C.maximum];
+	if(C.data_maximum <=TBLN)
+		C.data_maximum = lut[C.data_maximum];
+	if(C.maximum <= TBLN)
+		C.maximum = lut[C.maximum];
     // no need to adjust the minumum, black is already subtracted
     free(lut);
 }
@@ -2530,7 +2534,7 @@
 
         raw2image_ex(subtract_inline); // allocate imgdata.image and copy data!
 
-        int save_4color = O.four_color_rgb;
+		int save_4color = O.four_color_rgb;
 
         if (IO.zero_is_bad) 
           {
```
