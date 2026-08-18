# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3330_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3330_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2-43 of the vulnerable file.

// Part of ImageWorsener, Copyright (c) 2011 by Jason Summers.
// For more information, see the readme.txt file.

#define IW_INCLUDE_UTIL_FUNCTIONS
#include "imagew.h"

#define IW_COPYRIGHT_YEAR "2011" "\xe2\x80\x93" "2015"

#ifdef IW_WINDOWS
#define IW_INLINE __inline
#else
#define IW_INLINE inline
#endif

#define IW_MSG_MAX 200 // The usual max length of error messages, etc.

// Data type used for samples during some internal calculations
typedef double iw_tmpsample;

#ifdef IW_64BIT
#define IW_DEFAULT_MAX_DIMENSION 1000000
#define IW_DEFAULT_MAX_MALLOC 2000000000000
#else
#define IW_DEFAULT_MAX_DIMENSION 40000 // Must be less than sqrt(2^31).
#define IW_DEFAULT_MAX_MALLOC 2000000000
#endif

#define IW_BKGD_STRATEGY_EARLY 1 // Apply background before resizing
#define IW_BKGD_STRATEGY_LATE  2 // Apply background after resizing

#define IW_NUM_CHANNELTYPES 5 // 5, for R,G,B, Alpha, Gray
#define IW_CI_COUNT 4 // Number of channelinfo structs (=4, for R, G, B, A)

struct iw_rr_ctx; // "resize rows" state; see imagew-resize.c.

// "Raw" settings from the application.
struct iw_resize_settings {
	int family;
	int edge_policy;
	int use_offset;
	int disable_rrctx_cache;
	double param1; // 'B' in Mitchell-Netravali cubics. "lobes" in Lanczos, etc.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,8 +19,8 @@
 typedef double iw_tmpsample;
 
 #ifdef IW_64BIT
-#define IW_DEFAULT_MAX_DIMENSION 1000000
-#define IW_DEFAULT_MAX_MALLOC 2000000000000
+#define IW_DEFAULT_MAX_DIMENSION 40000
+#define IW_DEFAULT_MAX_MALLOC 2000000000
 #else
 #define IW_DEFAULT_MAX_DIMENSION 40000 // Must be less than sqrt(2^31).
 #define IW_DEFAULT_MAX_MALLOC 2000000000
```
