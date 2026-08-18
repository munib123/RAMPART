# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 629_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `629_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 72-113 of the vulnerable file.

    uint32_t mChannelBitmap;
    uint32_t mNumberChannelDescriptions;
} CAFChannelLayout;

#define CAFChannelLayoutFormat "LLL"

enum {
    kCAFChannelLayoutTag_UseChannelDescriptions = (0<<16) | 0,  // use the array of AudioChannelDescriptions to define the mapping.
    kCAFChannelLayoutTag_UseChannelBitmap = (1<<16) | 0,        // use the bitmap to define the mapping.
};

typedef struct
{
    uint32_t mChannelLabel;
    uint32_t mChannelFlags;
    float mCoordinates [3];
} CAFChannelDescription;

#define CAFChannelDescriptionFormat "LLLLL"

static const char TMH_full [] = { 1,2,3,13,9,10,5,6,12,14,15,16,17,9,4,18,7,8,19,20,21 };
static const char TMH_std [] = { 1,2,3,11,8,9,5,6,10,12,13,14,15,7,4,16 };

static struct {
    uint32_t mChannelLayoutTag;     // Core Audio layout, 100 - 146 in high word, num channels in low word
    uint32_t mChannelBitmap;        // Microsoft standard mask (for those channels that appear)
    const char *mChannelReorder;    // reorder string if layout is NOT in Microsoft standard order
    const char *mChannelIdentities; // identities of any channels NOT in Microsoft standard
} layouts [] = {
    { (100<<16) | 1, 0x004, NULL,       NULL            },  // FC
    { (101<<16) | 2, 0x003, NULL,       NULL            },  // FL, FR
    { (102<<16) | 2, 0x003, NULL,       NULL            },  // FL, FR (headphones)
    { (103<<16) | 2, 0x000, NULL,       "\46\47"        },  // [Lt, Rt] (matrix encoded)
    { (104<<16) | 2, 0x000, NULL,       "\314\315"      },  // [Mid, Side]
    { (105<<16) | 2, 0x000, NULL,       "\316\317"      },  // [X, Y]
    { (106<<16) | 2, 0x003, NULL,       NULL            },  // FL, FR (binaural)
    { (107<<16) | 4, 0x000, NULL,       "\310\311\312\313"  },  // [W, X, Y, Z] (ambisonics)
    { (108<<16) | 4, 0x033, NULL,       NULL            },  // FL, FR, BL, BR (quad)
    { (109<<16) | 5, 0x037, "12453",    NULL            },  // FL, FR, BL, BR, FC (pentagonal)
    { (110<<16) | 6, 0x137, "124536",   NULL            },  // FL, FR, BL, BR, FC, BC (hexagonal)
    { (111<<16) | 8, 0x737, "12453678", NULL            },  // FL, FR, BL, BR, FC, BC, SL, SR (octagonal)
    { (112<<16) | 8, 0x2d033, NULL,     NULL            },  // FL, FR, BL, BR, TFL, TFR, TBL, TBR (cubic)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,8 +89,8 @@
 
 #define CAFChannelDescriptionFormat "LLLLL"
 
-static const char TMH_full [] = { 1,2,3,13,9,10,5,6,12,14,15,16,17,9,4,18,7,8,19,20,21 };
-static const char TMH_std [] = { 1,2,3,11,8,9,5,6,10,12,13,14,15,7,4,16 };
+static const char TMH_full [] = { 1,2,3,13,9,10,5,6,12,14,15,16,17,9,4,18,7,8,19,20,21,0 };
+static const char TMH_std [] = { 1,2,3,11,8,9,5,6,10,12,13,14,15,7,4,16,0 };
 
 static struct {
     uint32_t mChannelLayoutTag;     // Core Audio layout, 100 - 146 in high word, num channels in low word
@@ -274,10 +274,19 @@
             }
         }
         else if (!strncmp (caf_chunk_header.mChunkType, "chan", 4)) {
-            CAFChannelLayout *caf_channel_layout = malloc ((size_t) caf_chunk_header.mChunkSize);
-
-            if (caf_chunk_header.mChunkSize < sizeof (CAFChannelLayout) ||
-                !DoReadFile (infile, caf_channel_layout, (uint32_t) caf_chunk_header.mChunkSize, &bcount) ||
+            CAFChannelLayout *caf_channel_layout;
+
+            if (caf_chunk_header.mChunkSize < sizeof (CAFChannelLayout) || caf_chunk_header.mChunkSize > 1024) {
+                error_line ("this .CAF file has an invalid 'chan' chunk!");
+                return WAVPACK_SOFT_ERROR;
+            }
+
+            if (debug_logging_mode)
+                error_line ("'chan' chunk is %d bytes", (int) caf_chunk_header.mChunkSize);
+
+            caf_channel_layout = malloc ((size_t) caf_chunk_header.mChunkSize);
+
+            if (!DoReadFile (infile, caf_channel_layout, (uint32_t) caf_chunk_header.mChunkSize, &bcount) ||
                 bcount != caf_chunk_header.mChunkSize) {
                     error_line ("%s is not a valid .CAF file!", infilename);
                     free (caf_channel_layout);
@@ -495,8 +504,15 @@
         }
         else {          // just copy unknown chunks to output file
 
-            int bytes_to_copy = (uint32_t) caf_chunk_header.mChunkSize;
-            char *buff = malloc (bytes_to_copy);
+            uint32_t bytes_to_copy = (uint32_t) caf_chunk_header.mChunkSize;
+            char *buff;
+
+            if (caf_chunk_header.mChunkSize < 0 || caf_chunk_header.mChunkSize > 1048576) {
+                error_line ("%s is not a valid .CAF file!", infilename);
+                return WAVPACK_SOFT_ERROR;
+            }
+
+            buff = malloc (bytes_to_copy);
 
             if (debug_logging_mode)
                 error_line ("extra unknown chunk \"%c%c%c%c\" of %d bytes",
```
