# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 840_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `840_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1725-1766 of the vulnerable file.

        /* create sample buffer (to catch read error with valgrind & sanitizers)  */
        sampleBuffer = (BYTE*)malloc(sampleSize);
        CHECK(sampleBuffer==NULL, "not enough memory for sample buffer");
        { size_t const sampleStart = FUZ_rand(&lseed) % (srcBufferSize - sampleSize);
          memcpy(sampleBuffer, srcBuffer + sampleStart, sampleSize); }
        crcOrig = XXH64(sampleBuffer, sampleSize, 0);

        /* compression tests */
        {   int const cLevelPositive =
                    ( FUZ_rand(&lseed) %
                     (ZSTD_maxCLevel() - (FUZ_highbit32((U32)sampleSize) / cLevelLimiter)) )
                    + 1;
            int const cLevel = ((FUZ_rand(&lseed) & 15) == 3) ?
                             - (int)((FUZ_rand(&lseed) & 7) + 1) :   /* test negative cLevel */
                             cLevelPositive;
            DISPLAYLEVEL(5, "fuzzer t%u: Simple compression test (level %i) \n", testNb, cLevel);
            cSize = ZSTD_compressCCtx(ctx, cBuffer, cBufferSize, sampleBuffer, sampleSize, cLevel);
            CHECK(ZSTD_isError(cSize), "ZSTD_compressCCtx failed : %s", ZSTD_getErrorName(cSize));

            /* compression failure test : too small dest buffer */
            if (cSize > 3) {
                const size_t missing = (FUZ_rand(&lseed) % (cSize-2)) + 1;   /* no problem, as cSize > 4 (frameHeaderSizer) */
                const size_t tooSmallSize = cSize - missing;
                const U32 endMark = 0x4DC2B1A9;
                memcpy(dstBuffer+tooSmallSize, &endMark, 4);
                { size_t const errorCode = ZSTD_compressCCtx(ctx, dstBuffer, tooSmallSize, sampleBuffer, sampleSize, cLevel);
                  CHECK(!ZSTD_isError(errorCode), "ZSTD_compressCCtx should have failed ! (buffer too small : %u < %u)", (U32)tooSmallSize, (U32)cSize); }
                { U32 endCheck; memcpy(&endCheck, dstBuffer+tooSmallSize, 4);
                  CHECK(endCheck != endMark, "ZSTD_compressCCtx : dst buffer overflow"); }
        }   }

        /* frame header decompression test */
        {   ZSTD_frameHeader zfh;
            CHECK_Z( ZSTD_getFrameHeader(&zfh, cBuffer, cSize) );
            CHECK(zfh.frameContentSize != sampleSize, "Frame content size incorrect");
        }

        /* Decompressed size test */
        {   unsigned long long const rSize = ZSTD_findDecompressedSize(cBuffer, cSize);
            CHECK(rSize != sampleSize, "decompressed size incorrect");
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1742,15 +1742,17 @@
             CHECK(ZSTD_isError(cSize), "ZSTD_compressCCtx failed : %s", ZSTD_getErrorName(cSize));
 
             /* compression failure test : too small dest buffer */
-            if (cSize > 3) {
-                const size_t missing = (FUZ_rand(&lseed) % (cSize-2)) + 1;   /* no problem, as cSize > 4 (frameHeaderSizer) */
+            assert(cSize > 3);
+            {   const size_t missing = (FUZ_rand(&lseed) % (cSize-2)) + 1;
                 const size_t tooSmallSize = cSize - missing;
                 const U32 endMark = 0x4DC2B1A9;
                 memcpy(dstBuffer+tooSmallSize, &endMark, 4);
+                DISPLAYLEVEL(5, "fuzzer t%u: compress into too small buffer of size %u (missing %u bytes) \n",
+                            testNb, (unsigned)tooSmallSize, (unsigned)missing);
                 { size_t const errorCode = ZSTD_compressCCtx(ctx, dstBuffer, tooSmallSize, sampleBuffer, sampleSize, cLevel);
                   CHECK(!ZSTD_isError(errorCode), "ZSTD_compressCCtx should have failed ! (buffer too small : %u < %u)", (U32)tooSmallSize, (U32)cSize); }
                 { U32 endCheck; memcpy(&endCheck, dstBuffer+tooSmallSize, 4);
-                  CHECK(endCheck != endMark, "ZSTD_compressCCtx : dst buffer overflow"); }
+                  CHECK(endCheck != endMark, "ZSTD_compressCCtx : dst buffer overflow  (check.%08X != %08X.mark)", endCheck, endMark); }
         }   }
 
         /* frame header decompression test */
```
