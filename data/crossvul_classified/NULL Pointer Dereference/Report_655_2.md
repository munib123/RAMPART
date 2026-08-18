# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 655_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `655_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 141-181 of the vulnerable file.


	/*< public >*/

	/* The image we generate. This must be set by ->header().
	 */
	VipsImage *out;

	/* The behind-the-scenes real image we decompress to. This can be a
	 * disc file or a memory buffer. This must be set by ->load().
	 */
	VipsImage *real;

	/* Set this to tag the operation as nocache.
	 */
	gboolean nocache;

	/* Deprecated: the memory option used to be called disc and default
	 * TRUE.
	 */
	gboolean disc;
} VipsForeignLoad;

typedef struct _VipsForeignLoadClass {
	VipsForeignClass parent_class;
	/*< public >*/

	/* Is a file in this format. 
	 *
	 * This function should return %TRUE if the file contains an image of 
	 * this type. If you don't define this function, #VipsForeignLoad
	 * will use @suffs instead.
	 */
	gboolean (*is_a)( const char *filename );

	/* Is a buffer in this format. 
	 *
	 * This function should return %TRUE if the buffer contains an image of 
	 * this type. 
	 */
	gboolean (*is_a_buffer)( const void *data, size_t size );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,6 +158,11 @@
 	 * TRUE.
 	 */
 	gboolean disc;
+
+	/* Set if a start function fails. We want to prevent the other starts
+	 * from also triggering the load.
+	 */
+	gboolean error;
 } VipsForeignLoad;
 
 typedef struct _VipsForeignLoadClass {
```
