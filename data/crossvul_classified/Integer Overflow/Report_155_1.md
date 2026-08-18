# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 155_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `155_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 827-866 of the vulnerable file.

  return (int)d.idx;
}

#ifdef ARM
extern int LINKER_END_VAR; // should be 'void', but 'int' avoids warnings
#endif

/** get the amount of free stack we have, in bytes */
size_t jsuGetFreeStack() {
#ifdef ARM
  void *frame = __builtin_frame_address(0);
  size_t stackPos = (size_t)((char*)frame);
  size_t stackEnd = (size_t)((char*)&LINKER_END_VAR);
  if (stackPos < stackEnd) return 0; // should never happen, but just in case of overflow!
  return  stackPos - stackEnd;
#elif defined(LINUX)
  // On linux, we set STACK_BASE from `main`.
  char ptr; // this is on the stack
  extern void *STACK_BASE;
  uint32_t count =  (uint32_t)((size_t)STACK_BASE - (size_t)&ptr);
  return 1000000 - count; // give it 1 megabyte of stack
#else
  // stack depth seems pretty platform-specific :( Default to a value that disables it
  return 1000000; // no stack depth check on this platform
#endif
}

unsigned int rand_m_w = 0xDEADBEEF;    /* must not be zero */
unsigned int rand_m_z = 0xCAFEBABE;    /* must not be zero */

int rand() {
  rand_m_z = 36969 * (rand_m_z & 65535) + (rand_m_z >> 16);
  rand_m_w = 18000 * (rand_m_w & 65535) + (rand_m_w >> 16);
  return (int)RAND_MAX & (int)((rand_m_z << 16) + rand_m_w);  /* 32-bit result */
}

void srand(unsigned int seed) {
  rand_m_w = (seed&0xFFFF) | (seed<<16);
  rand_m_z = (seed&0xFFFF0000) | (seed>>16);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -844,7 +844,9 @@
   char ptr; // this is on the stack
   extern void *STACK_BASE;
   uint32_t count =  (uint32_t)((size_t)STACK_BASE - (size_t)&ptr);
-  return 1000000 - count; // give it 1 megabyte of stack
+  const uint32_t max_stack = 1000000; // give it 1 megabyte of stack
+  if (count>max_stack) return 0;
+  return max_stack - count;
 #else
   // stack depth seems pretty platform-specific :( Default to a value that disables it
   return 1000000; // no stack depth check on this platform
```
