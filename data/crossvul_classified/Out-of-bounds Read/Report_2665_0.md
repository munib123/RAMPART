# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2665_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2665_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 93-136 of the vulnerable file.

}
#endif

static int
rip6_entry_print(netdissect_options *ndo, register const struct netinfo6 *ni, int metric)
{
	int l;
	l = ND_PRINT((ndo, "%s/%d", ip6addr_string(ndo, &ni->rip6_dest), ni->rip6_plen));
	if (ni->rip6_tag)
		l += ND_PRINT((ndo, " [%d]", EXTRACT_16BITS(&ni->rip6_tag)));
	if (metric)
		l += ND_PRINT((ndo, " (%d)", ni->rip6_metric));
	return l;
}

void
ripng_print(netdissect_options *ndo, const u_char *dat, unsigned int length)
{
	register const struct rip6 *rp = (const struct rip6 *)dat;
	register const struct netinfo6 *ni;
	register u_int amt;
	register u_int i;
	int j;
	int trunc;

	if (ndo->ndo_snapend < dat)
		return;
	amt = ndo->ndo_snapend - dat;
	i = min(length, amt);
	if (i < (sizeof(struct rip6) - sizeof(struct netinfo6)))
		return;
	i -= (sizeof(struct rip6) - sizeof(struct netinfo6));

	switch (rp->rip6_cmd) {

	case RIP6_REQUEST:
		j = length / sizeof(*ni);
		if (j == 1
		    &&  rp->rip6_nets->rip6_metric == HOPCNT_INFINITY6
		    &&  IN6_IS_ADDR_UNSPECIFIED(&rp->rip6_nets->rip6_dest)) {
			ND_PRINT((ndo, " ripng-req dump"));
			break;
		}
		if (j * sizeof(*ni) != length - 4)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,65 +110,74 @@
 {
 	register const struct rip6 *rp = (const struct rip6 *)dat;
 	register const struct netinfo6 *ni;
-	register u_int amt;
-	register u_int i;
-	int j;
-	int trunc;
+	unsigned int length_left;
+	u_int j;
 
-	if (ndo->ndo_snapend < dat)
-		return;
-	amt = ndo->ndo_snapend - dat;
-	i = min(length, amt);
-	if (i < (sizeof(struct rip6) - sizeof(struct netinfo6)))
-		return;
-	i -= (sizeof(struct rip6) - sizeof(struct netinfo6));
-
+	ND_TCHECK(rp->rip6_cmd);
 	switch (rp->rip6_cmd) {
 
 	case RIP6_REQUEST:
-		j = length / sizeof(*ni);
-		if (j == 1
-		    &&  rp->rip6_nets->rip6_metric == HOPCNT_INFINITY6
-		    &&  IN6_IS_ADDR_UNSPECIFIED(&rp->rip6_nets->rip6_dest)) {
-			ND_PRINT((ndo, " ripng-req dump"));
-			break;
+		length_left = length;
+		if (length_left < (sizeof(struct rip6) - sizeof(struct netinfo6)))
+			goto trunc;
+		length_left -= (sizeof(struct rip6) - sizeof(struct netinfo6));
+ 		j = length_left / sizeof(*ni);
+		if (j == 1) {
+			ND_TCHECK(rp->rip6_nets);
+			if (rp->rip6_nets->rip6_metric == HOPCNT_INFINITY6
+			    &&  IN6_IS_ADDR_UNSPECIFIED(&rp->rip6_nets->rip6_dest)) {
+				ND_PRINT((ndo, " ripng-req dump"));
+				break;
+			}
 		}
-		if (j * sizeof(*ni) != length - 4)
-			ND_PRINT((ndo, " ripng-req %d[%u]:", j, length));
+		if (j * sizeof(*ni) != length_left)
+			ND_PRINT((ndo, " ripng-req %u[%u]:", j, length));
 		else
-			ND_PRINT((ndo, " ripng-req %d:", j));
-		trunc = ((i / sizeof(*ni)) * sizeof(*ni) != i);
-		for (ni = rp->rip6_nets; i >= sizeof(*ni);
-		    i -= sizeof(*ni), ++ni) {
+			ND_PRINT((ndo, " ripng-req %u:", j));
+		for (ni = rp->rip6_nets; length_left >= sizeof(*ni);
+		    length_left -= sizeof(*ni), ++ni) {
+			ND_TCHECK(*ni);
 			if (ndo->ndo_vflag > 1)
 				ND_PRINT((ndo, "\n\t"));
 			else
 				ND_PRINT((ndo, " "));
 			rip6_entry_print(ndo, ni, 0);
 		}
+		if (length_left != 0)
+			goto trunc;
 		break;
 	case RIP6_RESPONSE:
-		j = length / sizeof(*ni);
-		if (j * sizeof(*ni) != length - 4)
+		length_left = length;
+		if (length_left < (sizeof(struct rip6) - sizeof(struct netinfo6)))
+			goto trunc;
+		length_left -= (sizeof(struct rip6) - sizeof(struct netinfo6));
+		j = length_left / sizeof(*ni);
+		if (j * sizeof(*ni) != length_left)
 			ND_PRINT((ndo, " ripng-resp %d[%u]:", j, length));
 		else
 			ND_PRINT((ndo, " ripng-resp %d:", j));
-		trunc = ((i / sizeof(*ni)) * sizeof(*ni) != i);
-		for (ni = rp->rip6_nets; i >= sizeof(*ni);
-		    i -= sizeof(*ni), ++ni) {
+		for (ni = rp->rip6_nets; length_left >= sizeof(*ni);
+		    length_left -= sizeof(*ni), ++ni) {
+			ND_TCHECK(*ni);
 			if (ndo->ndo_vflag > 1)
 				ND_PRINT((ndo, "\n\t"));
 			else
 				ND_PRINT((ndo, " "));
 			rip6_entry_print(ndo, ni, ni->rip6_metric);
 		}
-		if (trunc)
-			ND_PRINT((ndo, "[|ripng]"));
+		if (length_left != 0)
+			goto trunc;
 		break;
 	default:
 		ND_PRINT((ndo, " ripng-%d ?? %u", rp->rip6_cmd, length));
 		break;
 	}
+	ND_TCHECK(rp->rip6_vers);
 	if (rp->rip6_vers != RIP6_VERSION)
 		ND_PRINT((ndo, " [vers %d]", rp->rip6_vers));
+	return;
+
+trunc:
+	ND_PRINT((ndo, "[|ripng]"));
+	return;
 }
```
