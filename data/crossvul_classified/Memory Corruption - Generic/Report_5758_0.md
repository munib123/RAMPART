# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5758_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5758_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 553-593 of the vulnerable file.

 *
 *      Sends a specific RID directly to the driver to set configuration info.
 *
 *  PARAMETERS:
 *
 *      urq - a pointer to the UIL request buffer
 *      lp  - a pointer to the device's private adapter structure
 *
 *  RETURNS:
 *
 *      UIL_SUCCESS
 *      UIL_ERR_xxx value otherwise
 *
 ******************************************************************************/
int wvlan_uil_put_info(struct uilreq *urq, struct wl_private *lp)
{
	int                     result = 0;
	ltv_t                   *pLtv;
	bool_t                  ltvAllocated = FALSE;
	ENCSTRCT                sEncryption;

#ifdef USE_WDS
	hcf_16                  hcfPort  = HCF_PORT_0;
#endif  /* USE_WDS */
	/*------------------------------------------------------------------------*/
	DBG_FUNC("wvlan_uil_put_info");
	DBG_ENTER(DbgInfo);


	if (urq->hcfCtx == &(lp->hcfCtx)) {
		if (capable(CAP_NET_ADMIN)) {
			if ((urq->data != NULL) && (urq->len != 0)) {
				/* Make sure that we have at least a command and length to send. */
				if (urq->len < (sizeof(hcf_16) * 2)) {
					urq->len = sizeof(lp->ltvRecord);
					urq->result = UIL_ERR_LEN;
					DBG_ERROR(DbgInfo, "No Length/Type in LTV!!!\n");
					DBG_ERROR(DbgInfo, "UIL_ERR_LEN\n");
					DBG_LEAVE(DbgInfo);
					return result;
				}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -570,6 +570,7 @@
 	ltv_t                   *pLtv;
 	bool_t                  ltvAllocated = FALSE;
 	ENCSTRCT                sEncryption;
+	size_t			len;
 
 #ifdef USE_WDS
 	hcf_16                  hcfPort  = HCF_PORT_0;
@@ -686,7 +687,8 @@
 					break;
 				case CFG_CNF_OWN_NAME:
 					memset(lp->StationName, 0, sizeof(lp->StationName));
-					memcpy((void *)lp->StationName, (void *)&pLtv->u.u8[2], (size_t)pLtv->u.u16[0]);
+					len = min_t(size_t, pLtv->u.u16[0], sizeof(lp->StationName));
+					strlcpy(lp->StationName, &pLtv->u.u8[2], len);
 					pLtv->u.u16[0] = CNV_INT_TO_LITTLE(pLtv->u.u16[0]);
 					break;
 				case CFG_CNF_LOAD_BALANCING:
@@ -1783,6 +1785,7 @@
 {
 	struct wl_private *lp = wl_priv(dev);
 	unsigned long flags;
+	size_t len;
 	int         ret = 0;
 	/*------------------------------------------------------------------------*/
 
@@ -1793,8 +1796,8 @@
 	wl_lock(lp, &flags);
 
 	memset(lp->StationName, 0, sizeof(lp->StationName));
-
-	memcpy(lp->StationName, extra, wrqu->data.length);
+	len = min_t(size_t, wrqu->data.length, sizeof(lp->StationName));
+	strlcpy(lp->StationName, extra, len);
 
 	/* Commit the adapter parameters */
 	wl_apply(lp);
```
