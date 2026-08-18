# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 864_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `864_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 160-200 of the vulnerable file.

	switch(opcode) {
	case PCP_OPCODE_ANNOUNCE:
		return "ANNOUNCE";
	case PCP_OPCODE_MAP:
		return "MAP";
	case PCP_OPCODE_PEER:
		return "PEER";
#ifdef  PCP_SADSCP
	case PCP_OPCODE_SADSCP:
		return "SADSCP";
#endif	/* PCP_SADSCP */
	default:
		return "UNKNOWN";
	}
}

/* useful to copy ext_ip only if needed, as request and response
 * buffers are same */
static void copyIPv6IfDifferent(void * dest, const void * src)
{
	if(dest != src) {
		memcpy(dest, src, sizeof(struct in6_addr));
	}
}

#ifdef PCP_SADSCP
int get_dscp_value(pcp_info_t *pcp_msg_info) {

	unsigned int ind;

	for (ind = 0; ind < num_dscp_values; ind++) {

		if ((dscp_values_list[ind].app_name) &&
		    (!strcmp(dscp_values_list[ind].app_name,
			     pcp_msg_info->app_name)) &&
		    (pcp_msg_info->delay_tolerance == dscp_values_list[ind].delay) &&
		    (pcp_msg_info->loss_tolerance == dscp_values_list[ind].loss) &&
		    (pcp_msg_info->jitter_tolerance == dscp_values_list[ind].jitter)
		   )
		{
			pcp_msg_info->sadscp_dscp = dscp_values_list[ind].dscp_value;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -177,7 +177,7 @@
  * buffers are same */
 static void copyIPv6IfDifferent(void * dest, const void * src)
 {
-	if(dest != src) {
+	if(dest != src && src != NULL) {
 		memcpy(dest, src, sizeof(struct in6_addr));
 	}
 }
```
