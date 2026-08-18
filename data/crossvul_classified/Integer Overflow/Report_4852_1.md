# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4852_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4852_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 112-152 of the vulnerable file.

	/* The precinct height exponent. */
	int prcheightexpn;

	/* The number of precincts spanning the resolution level in the horizontal
	  direction. */
	int numhprcs;

} jpc_pirlvl_t;

/* Packet iterator per-component information. */

typedef struct {

	/* The number of resolution levels. */
	int numrlvls;

	/* The per-resolution-level information. */
	jpc_pirlvl_t *pirlvls;

	/* The horizontal sampling period. */
	int hsamp;

	/* The vertical sampling period. */
	int vsamp;

} jpc_picomp_t;

/* Packet iterator class. */

typedef struct {

	/* The number of layers. */
	int numlyrs;

	/* The number of resolution levels. */
	int maxrlvls;

	/* The number of components. */
	int numcomps;

	/* The per-component information. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,10 +129,10 @@
 	jpc_pirlvl_t *pirlvls;
 
 	/* The horizontal sampling period. */
-	int hsamp;
+	uint_fast32_t hsamp;
 
 	/* The vertical sampling period. */
-	int vsamp;
+	uint_fast32_t vsamp;
 
 } jpc_picomp_t;
 
@@ -171,32 +171,32 @@
 	int lyrno;
 
 	/* The x-coordinate of the current position. */
-	int x;
+	uint_fast32_t x;
 
 	/* The y-coordinate of the current position. */
-	int y;
+	uint_fast32_t y;
 
 	/* The horizontal step size. */
-	int xstep;
+	uint_fast32_t xstep;
 
 	/* The vertical step size. */
-	int ystep;
+	uint_fast32_t ystep;
 
 	/* The x-coordinate of the top-left corner of the tile on the reference
 	  grid. */
-	int xstart;
+	uint_fast32_t xstart;
 
 	/* The y-coordinate of the top-left corner of the tile on the reference
 	  grid. */
-	int ystart;
+	uint_fast32_t ystart;
 
 	/* The x-coordinate of the bottom-right corner of the tile on the
 	  reference grid (plus one). */
-	int xend;
+	uint_fast32_t xend;
 
 	/* The y-coordinate of the bottom-right corner of the tile on the
 	  reference grid (plus one). */
-	int yend;
+	uint_fast32_t yend;
 
 	/* The current progression change. */
 	jpc_pchg_t *pchg;
```
