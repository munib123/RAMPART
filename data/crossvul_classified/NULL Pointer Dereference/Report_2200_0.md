# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2200_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2200_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1425-1465 of the vulnerable file.

	     gss_buffer_t *mechListMIC,
	     OM_uint32 *negState,
	     send_token_flag *return_token)
{
	OM_uint32 ret, tmpmin;
	gss_OID supportedMech;
	spnego_gss_ctx_id_t sc;
	unsigned int len;
	unsigned char *ptr, *bufstart;

	sc = (spnego_gss_ctx_id_t)*ctx;
	ret = GSS_S_DEFECTIVE_TOKEN;
	*negState = REJECT;
	*minstat = 0;
	supportedMech = GSS_C_NO_OID;
	*return_token = ERROR_TOKEN_SEND;
	*responseToken = *mechListMIC = GSS_C_NO_BUFFER;

	ptr = bufstart = buf->value;
#define REMAIN (buf->length - (ptr - bufstart))
	if (REMAIN > INT_MAX)
		return GSS_S_DEFECTIVE_TOKEN;

	/*
	 * Attempt to work with old Sun SPNEGO.
	 */
	if (*ptr == HEADER_ID) {
		ret = g_verify_token_header(gss_mech_spnego,
					    &len, &ptr, 0, REMAIN);
		if (ret) {
			*minstat = ret;
			return GSS_S_DEFECTIVE_TOKEN;
		}
	}
	if (*ptr != (CONTEXT | 0x01)) {
		return GSS_S_DEFECTIVE_TOKEN;
	}
	ret = get_negTokenResp(minstat, ptr, REMAIN,
			       negState, &supportedMech,
			       responseToken, mechListMIC);
	if (ret != GSS_S_COMPLETE)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1442,7 +1442,7 @@
 
 	ptr = bufstart = buf->value;
 #define REMAIN (buf->length - (ptr - bufstart))
-	if (REMAIN > INT_MAX)
+	if (REMAIN == 0 || REMAIN > INT_MAX)
 		return GSS_S_DEFECTIVE_TOKEN;
 
 	/*
```
