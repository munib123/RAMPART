# CrossVul Fix Pair: Incorrect Type Conversion or Cast in c
**Pair ID:** 1659_1
**Vulnerability Class:** Type Confusion
**CWE:** CWE-704
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1659_1`)

## Vulnerability Information & PoC

## Description
Incorrect Type Conversion or Cast - The product does not correctly convert an object, resource, or structure from one type to a different type.

## Vulnerable Code
```c
Lines 139-180 of the vulnerable file.

 * Limits of things
 */
#define	MAXFILENAME	256	/* max length of file name */
#define MAXHOSTNAME	512	/* max length of host/node name */
#define NTP_MAXSTRLEN	256	/* max string length */

/*
 * Operations for jitter calculations (these use doubles).
 *
 * Note that we carefully separate the jitter component from the
 * dispersion component (frequency error plus precision). The frequency
 * error component is computed as CLOCK_PHI times the difference between
 * the epoch of the time measurement and the reference time. The
 * precision component is computed as the square root of the mean of the
 * squares of a zero-mean, uniform distribution of unit maximum
 * amplitude. Whether this makes statistical sense may be arguable.
 */
#define SQUARE(x) ((x) * (x))
#define SQRT(x) (sqrt(x))
#define DIFF(x, y) (SQUARE((x) - (y)))
#define LOGTOD(a)	((a) < 0 ? 1. / (1L << -(a)) : \
			    1L << (int)(a)) /* log2 to double */
#define UNIVAR(x)	(SQUARE(.28867513 * LOGTOD(x))) /* std uniform distr */
#define ULOGTOD(a)	(1L << (int)(a)) /* ulog2 to double */

#define	EVENT_TIMEOUT	0	/* one second, that is */


/*
 * The interface structure is used to hold the addresses and socket
 * numbers of each of the local network addresses we are using.
 * Because "interface" is a reserved word in C++ and has so many
 * varied meanings, a change to "endpt" (via typedef) is under way.
 * Eventually the struct tag will change from interface to endpt_tag.
 * endpt is unrelated to the select algorithm's struct endpoint.
 */
typedef struct interface endpt;
struct interface {
	endpt *		elink;		/* endpt list link */
	endpt *		mclink;		/* per-AF_* multicast list */
	SOCKET		fd;		/* socket descriptor */
	SOCKET		bfd;		/* for receiving broadcasts */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,10 +156,9 @@
 #define SQUARE(x) ((x) * (x))
 #define SQRT(x) (sqrt(x))
 #define DIFF(x, y) (SQUARE((x) - (y)))
-#define LOGTOD(a)	((a) < 0 ? 1. / (1L << -(a)) : \
-			    1L << (int)(a)) /* log2 to double */
+#define LOGTOD(a)	ldexp(1., (int)(a)) /* log2 to double */
 #define UNIVAR(x)	(SQUARE(.28867513 * LOGTOD(x))) /* std uniform distr */
-#define ULOGTOD(a)	(1L << (int)(a)) /* ulog2 to double */
+#define ULOGTOD(a)	ldexp(1., (int)(a)) /* ulog2 to double */
 
 #define	EVENT_TIMEOUT	0	/* one second, that is */
 
```
