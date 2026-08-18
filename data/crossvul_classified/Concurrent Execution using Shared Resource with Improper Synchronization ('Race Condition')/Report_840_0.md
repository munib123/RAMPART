# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 840_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `840_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1991-2031 of the vulnerable file.

            return set_repeat;
        }
        assert(compressedCost < basicCost && compressedCost < repeatCost);
    }
    DEBUGLOG(5, "Selected set_compressed");
    *repeatMode = FSE_repeat_check;
    return set_compressed;
}

MEM_STATIC size_t
ZSTD_buildCTable(void* dst, size_t dstCapacity,
                FSE_CTable* nextCTable, U32 FSELog, symbolEncodingType_e type,
                U32* count, U32 max,
                const BYTE* codeTable, size_t nbSeq,
                const S16* defaultNorm, U32 defaultNormLog, U32 defaultMax,
                const FSE_CTable* prevCTable, size_t prevCTableSize,
                void* workspace, size_t workspaceSize)
{
    BYTE* op = (BYTE*)dst;
    const BYTE* const oend = op + dstCapacity;

    switch (type) {
    case set_rle:
        *op = codeTable[0];
        CHECK_F(FSE_buildCTable_rle(nextCTable, (BYTE)max));
        return 1;
    case set_repeat:
        memcpy(nextCTable, prevCTable, prevCTableSize);
        return 0;
    case set_basic:
        CHECK_F(FSE_buildCTable_wksp(nextCTable, defaultNorm, defaultMax, defaultNormLog, workspace, workspaceSize));  /* note : could be pre-calculated */
        return 0;
    case set_compressed: {
        S16 norm[MaxSeq + 1];
        size_t nbSeq_1 = nbSeq;
        const U32 tableLog = FSE_optimalTableLog(FSELog, nbSeq, max);
        if (count[codeTable[nbSeq-1]] > 1) {
            count[codeTable[nbSeq-1]]--;
            nbSeq_1--;
        }
        assert(nbSeq_1 > 1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2008,11 +2008,13 @@
 {
     BYTE* op = (BYTE*)dst;
     const BYTE* const oend = op + dstCapacity;
+    DEBUGLOG(6, "ZSTD_buildCTable (dstCapacity=%u)", (unsigned)dstCapacity);
 
     switch (type) {
     case set_rle:
+        CHECK_F(FSE_buildCTable_rle(nextCTable, (BYTE)max));
+        if (dstCapacity==0) return ERROR(dstSize_tooSmall);
         *op = codeTable[0];
-        CHECK_F(FSE_buildCTable_rle(nextCTable, (BYTE)max));
         return 1;
     case set_repeat:
         memcpy(nextCTable, prevCTable, prevCTableSize);
@@ -2054,6 +2056,9 @@
     FSE_CState_t  stateLitLength;
 
     CHECK_E(BIT_initCStream(&blockStream, dst, dstCapacity), dstSize_tooSmall); /* not enough space remaining */
+    DEBUGLOG(6, "available space for bitstream : %i  (dstCapacity=%u)",
+                (int)(blockStream.endPtr - blockStream.startPtr),
+                (unsigned)dstCapacity);
 
     /* first symbols */
     FSE_initCState2(&stateMatchLength, CTable_MatchLength, mlCodeTable[nbSeq-1]);
@@ -2113,6 +2118,7 @@
                 BIT_addBits(&blockStream, sequences[n].offset, ofBits);     /* 31 */
             }
             BIT_flushBits(&blockStream);                                    /* (7)*/
+            DEBUGLOG(7, "remaining space : %i", (int)(blockStream.endPtr - blockStream.ptr));
     }   }
 
     DEBUGLOG(6, "ZSTD_encodeSequences: flushing ML state with %u bits", stateMatchLength.stateLog);
@@ -2170,6 +2176,7 @@
             FSE_CTable const* CTable_LitLength, BYTE const* llCodeTable,
             seqDef const* sequences, size_t nbSeq, int longOffsets, int bmi2)
 {
+    DEBUGLOG(5, "ZSTD_encodeSequences: dstCapacity = %u", (unsigned)dstCapacity);
 #if DYNAMIC_BMI2
     if (bmi2) {
         return ZSTD_encodeSequences_bmi2(dst, dstCapacity,
@@ -2290,7 +2297,7 @@
     /* build CTable for MatchLengths */
     {   U32 max = MaxML;
         size_t const mostFrequent = HIST_countFast_wksp(count, &max, mlCodeTable, nbSeq, workspace, wkspSize);   /* can't fail */
-        DEBUGLOG(5, "Building ML table");
+        DEBUGLOG(5, "Building ML table (remaining space : %i)", (int)(oend-op));
         nextEntropy->fse.matchlength_repeatMode = prevEntropy->fse.matchlength_repeatMode;
         MLtype = ZSTD_selectEncodingType(&nextEntropy->fse.matchlength_repeatMode, count, max, mostFrequent, nbSeq, MLFSELog, prevEntropy->fse.matchlengthCTable, ML_defaultNorm, ML_defaultNormLog, ZSTD_defaultAllowed, strategy);
         assert(!(MLtype < set_compressed && nextEntropy->fse.matchlength_repeatMode != FSE_repeat_none)); /* We don't copy tables */
```
