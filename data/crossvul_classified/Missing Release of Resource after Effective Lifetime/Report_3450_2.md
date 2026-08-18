# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 3450_2
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3450_2`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 154-194 of the vulnerable file.




/* This function is similar to processBatch(), but works on a batch that
 * contains rules from multiple rulesets. In this case, we can not push
 * the whole batch through the ruleset. Instead, we examine it and
 * partition it into sub-rulesets which we then push through the system.
 * Note that when we evaluate which message must be processed, we do NOT need
 * to look at bFilterOK, because this value is only set in a later processing
 * stage. Doing so caused a bug during development ;)
 * rgerhards, 2010-06-15
 */
static inline rsRetVal
processBatchMultiRuleset(batch_t *pBatch)
{
	ruleset_t *currRuleset;
	batch_t snglRuleBatch;
	int i;
	int iStart;	/* start index of partial batch */
	int iNew;	/* index for new (temporary) batch */
	DEFiRet;

	CHKiRet(batchInit(&snglRuleBatch, pBatch->nElem));
	snglRuleBatch.pbShutdownImmediate = pBatch->pbShutdownImmediate;

	while(1) { /* loop broken inside */
		/* search for first unprocessed element */
		for(iStart = 0 ; iStart < pBatch->nElem && pBatch->pElem[iStart].state == BATCH_STATE_DISC ; ++iStart)
			/* just search, no action */;

		if(iStart == pBatch->nElem)
			FINALIZE; /* everything processed */

		/* prepare temporary batch */
		currRuleset = batchElemGetRuleset(pBatch, iStart);
		iNew = 0;
		for(i = iStart ; i < pBatch->nElem ; ++i) {
			if(batchElemGetRuleset(pBatch, i) == currRuleset) {
				batchCopyElem(&(snglRuleBatch.pElem[iNew++]), &(pBatch->pElem[i]));
				/* We indicate the element also as done, so it will not be processed again */
				pBatch->pElem[i].state = BATCH_STATE_DISC;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,35 +171,40 @@
 	int i;
 	int iStart;	/* start index of partial batch */
 	int iNew;	/* index for new (temporary) batch */
-	DEFiRet;
-
-	CHKiRet(batchInit(&snglRuleBatch, pBatch->nElem));
-	snglRuleBatch.pbShutdownImmediate = pBatch->pbShutdownImmediate;
-
-	while(1) { /* loop broken inside */
+	int bHaveUnprocessed;	/* do we (still) have unprocessed entries? (loop term predicate) */
+	DEFiRet;
+
+	do {
+		bHaveUnprocessed = 0;
 		/* search for first unprocessed element */
 		for(iStart = 0 ; iStart < pBatch->nElem && pBatch->pElem[iStart].state == BATCH_STATE_DISC ; ++iStart)
 			/* just search, no action */;
-
 		if(iStart == pBatch->nElem)
-			FINALIZE; /* everything processed */
+			break; /* everything processed */
 
 		/* prepare temporary batch */
+		CHKiRet(batchInit(&snglRuleBatch, pBatch->nElem));
+		snglRuleBatch.pbShutdownImmediate = pBatch->pbShutdownImmediate;
 		currRuleset = batchElemGetRuleset(pBatch, iStart);
 		iNew = 0;
 		for(i = iStart ; i < pBatch->nElem ; ++i) {
 			if(batchElemGetRuleset(pBatch, i) == currRuleset) {
-				batchCopyElem(&(snglRuleBatch.pElem[iNew++]), &(pBatch->pElem[i]));
+				/* for performance reasons, we copy only those members that we actually need */
+				snglRuleBatch.pElem[iNew].pUsrp = pBatch->pElem[i].pUsrp;
+				snglRuleBatch.pElem[iNew].state = pBatch->pElem[i].state;
+				++iNew;
 				/* We indicate the element also as done, so it will not be processed again */
 				pBatch->pElem[i].state = BATCH_STATE_DISC;
+			} else {
+				bHaveUnprocessed = 1;
 			}
 		}
 		snglRuleBatch.nElem = iNew; /* was left just right by the for loop */
 		batchSetSingleRuleset(&snglRuleBatch, 1);
 		/* process temp batch */
 		processBatch(&snglRuleBatch);
-	}
-	batchFree(&snglRuleBatch);
+		batchFree(&snglRuleBatch);
+	} while(bHaveUnprocessed == 1);
 
 finalize_it:
 	RETiRet;
```
