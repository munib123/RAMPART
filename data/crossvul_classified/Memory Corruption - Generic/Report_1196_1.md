# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1196_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1196_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 31-71 of the vulnerable file.

 * N.B. This is the "Composite Document File" format, and not the
 * "Compound Document Format", nor the "Channel Definition Format".
 */

#ifndef _H_CDF_
#define _H_CDF_

#ifdef WIN32
#include <winsock2.h>
#define timespec timeval
#define tv_nsec tv_usec
#endif
#ifdef __DJGPP__
#define timespec timeval
#define tv_nsec tv_usec
#endif

typedef int32_t cdf_secid_t;

#define CDF_LOOP_LIMIT					10000

#define CDF_SECID_NULL					0
#define CDF_SECID_FREE					-1
#define CDF_SECID_END_OF_CHAIN				-2
#define CDF_SECID_SECTOR_ALLOCATION_TABLE		-3
#define CDF_SECID_MASTER_SECTOR_ALLOCATION_TABLE	-4

typedef struct {
	uint64_t	h_magic;
#define CDF_MAGIC	0xE11AB1A1E011CFD0LL
	uint64_t	h_uuid[2];
	uint16_t	h_revision;
	uint16_t	h_version;
	uint16_t	h_byte_order;
	uint16_t	h_sec_size_p2;
	uint16_t	h_short_sec_size_p2;
	uint8_t		h_unused0[10];
	uint32_t	h_num_sectors_in_sat;
	uint32_t	h_secid_first_directory;
	uint8_t		h_unused1[4];
	uint32_t	h_min_size_standard_stream;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,7 @@
 typedef int32_t cdf_secid_t;
 
 #define CDF_LOOP_LIMIT					10000
+#define CDF_ELEMENT_LIMIT				100000
 
 #define CDF_SECID_NULL					0
 #define CDF_SECID_FREE					-1
```
