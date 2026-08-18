# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3237_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3237_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1-26 of the vulnerable file.

/* Capstone Disassembly Engine */
/* By Satoshi Tanda <tanda.sat@gmail.com>, 2016 */

#include "winkernel_mm.h"
#include <ntddk.h>

// A pool tag for memory allocation
static const ULONG CS_WINKERNEL_POOL_TAG = 'kwsC';


// A structure to implement realloc()
typedef struct _CS_WINKERNEL_MEMBLOCK {
	size_t size;   // A number of bytes allocated
	char data[1];  // An address returned to a caller
} CS_WINKERNEL_MEMBLOCK;
C_ASSERT(sizeof(CS_WINKERNEL_MEMBLOCK) == sizeof(void *) * 2);


// free()
void CAPSTONE_API cs_winkernel_free(void *ptr)
{
	if (ptr) {
		ExFreePoolWithTag(CONTAINING_RECORD(ptr, CS_WINKERNEL_MEMBLOCK, data), CS_WINKERNEL_POOL_TAG);
	}
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,7 @@
 
 #include "winkernel_mm.h"
 #include <ntddk.h>
+#include <Ntintsafe.h>
 
 // A pool tag for memory allocation
 static const ULONG CS_WINKERNEL_POOL_TAG = 'kwsC';
@@ -33,8 +34,16 @@
 
 	// FP; a use of NonPagedPool is required for Windows 7 support
 #pragma prefast(suppress : 30030)		// Allocating executable POOL_TYPE memory
-	CS_WINKERNEL_MEMBLOCK *block = (CS_WINKERNEL_MEMBLOCK *)ExAllocatePoolWithTag(
-			NonPagedPool, size + sizeof(CS_WINKERNEL_MEMBLOCK), CS_WINKERNEL_POOL_TAG);
+	size_t number_of_bytes = 0;
+	CS_WINKERNEL_MEMBLOCK *block = NULL;
+	// A specially crafted size value can trigger the overflow.
+	// If the sum in a value that overflows or underflows the capacity of the type,
+	// the function returns NULL.
+	if (!NT_SUCCESS(RtlSizeTAdd(size, sizeof(CS_WINKERNEL_MEMBLOCK), &number_of_bytes))) {
+		return NULL;
+	}
+	block = (CS_WINKERNEL_MEMBLOCK *)ExAllocatePoolWithTag(
+			NonPagedPool, number_of_bytes, CS_WINKERNEL_POOL_TAG);
 	if (!block) {
 		return NULL;
 	}
```
