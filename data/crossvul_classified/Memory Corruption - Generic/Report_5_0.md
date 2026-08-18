# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-28 of the vulnerable file.

// Ogg Vorbis audio decoder - v1.11 - public domain
// http://nothings.org/stb_vorbis/
//
// Original version written by Sean Barrett in 2007.
//
// Originally sponsored by RAD Game Tools. Seeking sponsored
// by Phillip Bennefall, Marc Andersen, Aaron Baker, Elias Software,
// Aras Pranckevicius, and Sean Barrett.
//
// LICENSE
//
//   See end of file for license information.
//
// Limitations:
//
//   - floor 0 not supported (used in old ogg vorbis files pre-2004)
//   - lossless sample-truncation at beginning ignored
//   - cannot concatenate multiple vorbis streams
//   - sample positions are 32-bit, limiting seekable 192Khz
//       files to around 6 hours (Ogg supports 64-bit)
//
// Feature contributors:
//    Dougall Johnson (sample-exact seeking)
//
// Bugfix/warning contributors:
//    Terje Mathisen     Niklas Frykholm     Andy Hill
//    Casey Muratori     John Bolton         Gargaj
//    Laurent Gomila     Marc LeBlanc        Ronny Chevalier
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,9 +3,9 @@
 //
 // Original version written by Sean Barrett in 2007.
 //
-// Originally sponsored by RAD Game Tools. Seeking sponsored
-// by Phillip Bennefall, Marc Andersen, Aaron Baker, Elias Software,
-// Aras Pranckevicius, and Sean Barrett.
+// Originally sponsored by RAD Game Tools. Seeking implementation
+// sponsored by Phillip Bennefall, Marc Andersen, Aaron Baker,
+// Elias Software, Aras Pranckevicius, and Sean Barrett.
 //
 // LICENSE
 //
@@ -32,6 +32,7 @@
 //    manxorist@github   saga musix          github:infatum
 //
 // Partial history:
+//    1.12    - 2017/11/21 - limit residue begin/end to blocksize/2 to avoid large temp allocs in bad/corrupt files
 //    1.11    - 2017/07/23 - fix MinGW compilation 
 //    1.10    - 2017/03/03 - more robust seeking; fix negative ilog(); clear error in open_memory
 //    1.09    - 2016/04/04 - back out 'truncation of last frame' fix from previous version
@@ -2042,6 +2043,8 @@
    return TRUE;
 }
 
+// n is 1/2 of the blocksize --
+// specification: "Correct per-vector decode length is [n]/2"
 static void decode_residue(vorb *f, float *residue_buffers[], int ch, int n, int rn, uint8 *do_not_decode)
 {
    int i,j,pass;
@@ -2049,7 +2052,10 @@
    int rtype = f->residue_types[rn];
    int c = r->classbook;
    int classwords = f->codebooks[c].dimensions;
-   int n_read = r->end - r->begin;
+   unsigned int actual_size = rtype == 2 ? n*2 : n;
+   unsigned int limit_r_begin = (r->begin < actual_size ? r->begin : actual_size);
+   unsigned int limit_r_end   = (r->end   < actual_size ? r->end   : actual_size);
+   int n_read = limit_r_end - limit_r_begin;
    int part_read = n_read / r->part_size;
    int temp_alloc_point = temp_alloc_save(f);
    #ifndef STB_VORBIS_DIVIDES_IN_RESIDUE
@@ -4077,7 +4083,10 @@
       int i,max_part_read=0;
       for (i=0; i < f->residue_count; ++i) {
          Residue *r = f->residue_config + i;
-         int n_read = r->end - r->begin;
+         unsigned int actual_size = f->blocksize_1 / 2;
+         unsigned int limit_r_begin = r->begin < actual_size ? r->begin : actual_size;
+         unsigned int limit_r_end   = r->end   < actual_size ? r->end   : actual_size;
+         int n_read = limit_r_end - limit_r_begin;
          int part_read = n_read / r->part_size;
          if (part_read > max_part_read)
             max_part_read = part_read;
@@ -4087,6 +4096,8 @@
       #else
       classify_mem = f->channels * (sizeof(void*) + max_part_read * sizeof(int *));
       #endif
+
+      // maximum reasonable partition size is f->blocksize_1
 
       f->temp_memory_required = classify_mem;
       if (imdct_mem > f->temp_memory_required)
@@ -5351,6 +5362,8 @@
 #endif // STB_VORBIS_NO_PULLDATA_API
 
 /* Version history
+    1.12    - 2017/11/21 - limit residue begin/end to blocksize/2 to avoid large temp allocs in bad/corrupt files
+    1.11    - 2017/07/23 - fix MinGW compilation 
     1.10    - 2017/03/03 - more robust seeking; fix negative ilog(); clear error in open_memory
     1.09    - 2016/04/04 - back out 'avoid discarding last frame' fix from previous version
     1.08    - 2016/04/02 - fixed multiple warnings; fix setup memory leaks;
```
