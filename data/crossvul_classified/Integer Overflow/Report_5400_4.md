# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5400_4
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5400_4`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 250-290 of the vulnerable file.

 */
typedef struct {
	int fd;
	int flags;
	char pathname[L_tmpnam + 1];
} jas_stream_fileobj_t;

#define	JAS_STREAM_FILEOBJ_DELONCLOSE	0x01
#define JAS_STREAM_FILEOBJ_NOCLOSE	0x02

/*
 * Memory file object.
 */

typedef struct {

	/* The data associated with this file. */
	uchar *buf_;

	/* The allocated size of the buffer for holding file data. */
	int bufsize_;

	/* The length of the file. */
	int_fast32_t len_;

	/* The seek position. */
	int_fast32_t pos_;

	/* Is the buffer growable? */
	int growable_;

	/* Was the buffer allocated internally? */
	int myalloc_;

} jas_stream_memobj_t;

/******************************************************************************\
* Macros/functions for opening and closing streams.
\******************************************************************************/

/* Open a file as a stream. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -267,7 +267,7 @@
 	uchar *buf_;
 
 	/* The allocated size of the buffer for holding file data. */
-	int bufsize_;
+	size_t bufsize_;
 
 	/* The length of the file. */
 	int_fast32_t len_;
@@ -292,6 +292,10 @@
 
 /* Open a memory buffer as a stream. */
 jas_stream_t *jas_stream_memopen(char *buf, int bufsize);
+
+/* Do not use this function.
+It will eventually replace jas_stream_memopen. */
+jas_stream_t *jas_stream_memopen2(char *buf, size_t bufsize);
 
 /* Open a file descriptor as a stream. */
 jas_stream_t *jas_stream_fdopen(int fd, const char *mode);
```
