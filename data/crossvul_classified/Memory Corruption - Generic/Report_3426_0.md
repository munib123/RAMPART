# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3426_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3426_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 133-173 of the vulnerable file.

#define DEBUG( a ) printf( a )
#define DEBUG2( a,b ) printf( a,b )
#define DEBUG3( a,b,c ) printf( a,b,c )
#define DEBUG4( a,b,c,d ) printf( a,b,c,d )
#else
#define DEBUG( a )
#define DEBUG2( a,b ) 
#define DEBUG3( a,b,c ) 
#define DEBUG4( a,b,c,d ) 
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif
/**
 * The highest value a variable of type off_t can reach. This is a signed
 * integer, so set all bits except for the leftmost one.
 **/
#define OFFT_MAX ~((off_t)1<<(sizeof(off_t)*8-1))
#define LINELEN 256	  /**< Size of static buffer used to read the
			       authorization file (yuck) */
#define BUFSIZE (1024*1024) /**< Size of buffer that can hold requests */
#define DIFFPAGESIZE 4096 /**< diff file uses those chunks */
#define F_READONLY 1      /**< flag to tell us a file is readonly */
#define F_MULTIFILE 2	  /**< flag to tell us a file is exported using -m */
#define F_COPYONWRITE 4	  /**< flag to tell us a file is exported using
			    copyonwrite */
#define F_AUTOREADONLY 8  /**< flag to tell us a file is set to autoreadonly */
#define F_SPARSE 16	  /**< flag to tell us copyronwrite should use a sparse file */
#define F_SDP 32	  /**< flag to tell us the export should be done using the Socket Direct Protocol for RDMA */
#define F_SYNC 64	  /**< Whether to fsync() after a write */
GHashTable *children;
char pidfname[256]; /**< name of our PID file */
char pidftemplate[256]; /**< template to be used for the filename of the PID file */
char default_authname[] = SYSCONFDIR "/nbd-server/allow"; /**< default name of allow file */

int modernsock=0;	  /**< Socket for the modern handler. Not used
			       if a client was only specified on the
			       command line; only port used if
			       oldstyle is set to false (and then the
			       command-line client isn't used, gna gna) */
char* modern_listen;	  /**< listenaddr value for modernsock */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,7 +150,7 @@
 #define OFFT_MAX ~((off_t)1<<(sizeof(off_t)*8-1))
 #define LINELEN 256	  /**< Size of static buffer used to read the
 			       authorization file (yuck) */
-#define BUFSIZE (1024*1024) /**< Size of buffer that can hold requests */
+#define BUFSIZE ((1024*1024)+sizeof(struct nbd_reply)) /**< Size of buffer that can hold requests */
 #define DIFFPAGESIZE 4096 /**< diff file uses those chunks */
 #define F_READONLY 1      /**< flag to tell us a file is readonly */
 #define F_MULTIFILE 2	  /**< flag to tell us a file is exported using -m */
@@ -1389,7 +1389,7 @@
 
 		if (request.magic != htonl(NBD_REQUEST_MAGIC))
 			err("Not enough magic.");
-		if (len > BUFSIZE + sizeof(struct nbd_reply))
+		if (len > BUFSIZE - sizeof(struct nbd_reply))
 			err("Request too big!");
 #ifdef DODBG
 		printf("%s from %llu (%llu) len %d, ", request.type ? "WRITE" :
```
