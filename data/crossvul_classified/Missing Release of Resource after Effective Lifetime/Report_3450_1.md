# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 3450_1
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3450_1`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 119-159 of the vulnerable file.

 */
static inline void
batchSetElemState(batch_t *pBatch, int i, batch_state_t newState) {
	if(pBatch->pElem[i].state != BATCH_STATE_DISC)
		pBatch->pElem[i].state = newState;
}


/* check if an element is a valid entry. We do NOT verify if the
 * element index is valid. -- rgerhards, 2010-06-10
 */
static inline int
batchIsValidElem(batch_t *pBatch, int i) {
	return(pBatch->pElem[i].bFilterOK && pBatch->pElem[i].state != BATCH_STATE_DISC);
}


/* copy one batch element to another.
 * This creates a complete duplicate in those cases where
 * it is needed. Use duplication only when absolutely necessary!
 * rgerhards, 2010-06-10
 */
static inline void
batchCopyElem(batch_obj_t *pDest, batch_obj_t *pSrc) {
	memcpy(pDest, pSrc, sizeof(batch_obj_t));
}


/* free members of a batch "object". Note that we can not do the usual
 * destruction as the object typically is allocated on the stack and so the
 * object itself cannot be freed! -- rgerhards, 2010-06-15
 */
static inline void
batchFree(batch_t *pBatch) {
	int i;
	int j;
	for(i = 0 ; i < pBatch->maxElem ; ++i) {
		for(j = 0 ; j < CONF_OMOD_NUMSTRINGS_MAXSIZE ; ++j) {
			/* staticActParams MUST be freed immediately (if required),
			 * so we do not need to do that!
			 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,11 +136,16 @@
 /* copy one batch element to another.
  * This creates a complete duplicate in those cases where
  * it is needed. Use duplication only when absolutely necessary!
+ * Note that all working fields are reset to zeros. If that were 
+ * not done, we would have potential problems with invalid
+ * or double pointer frees.
  * rgerhards, 2010-06-10
  */
 static inline void
 batchCopyElem(batch_obj_t *pDest, batch_obj_t *pSrc) {
-	memcpy(pDest, pSrc, sizeof(batch_obj_t));
+	memset(pDest, 0, sizeof(batch_obj_t));
+	pDest->pUsrp = pSrc->pUsrp;
+	pDest->state = pSrc->state;
 }
 
 
@@ -171,6 +176,7 @@
 static inline rsRetVal
 batchInit(batch_t *pBatch, int maxElem) {
 	DEFiRet;
+	pBatch->iDoneUpTo = 0;
 	pBatch->maxElem = maxElem;
 	CHKmalloc(pBatch->pElem = calloc((size_t)maxElem, sizeof(batch_obj_t)));
 	// TODO: replace calloc by inidividual writes?
```
