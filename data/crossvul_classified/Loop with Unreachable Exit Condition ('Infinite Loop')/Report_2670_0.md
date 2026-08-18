# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2670_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2670_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 634-674 of the vulnerable file.

static void
print_tsa_assignment_table(netdissect_options *ndo,
                           const u_char *ptr)
{
    ND_PRINT((ndo, "\n\t    TSA Assignment Table"));
    ND_PRINT((ndo, "\n\t     Traffic Class: 0   1   2   3   4   5   6   7"));
    ND_PRINT((ndo, "\n\t     Value        : %-3d %-3d %-3d %-3d %-3d %-3d %-3d %-3d",
             ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]));
}

/*
 * Print IEEE 802.1 private extensions. (802.1AB annex E)
 */
static int
lldp_private_8021_print(netdissect_options *ndo,
                        const u_char *tptr, u_int tlv_len)
{
    int subtype, hexdump = FALSE;
    u_int sublen;
    u_int tval;
    uint8_t i;

    if (tlv_len < 4) {
        return hexdump;
    }
    subtype = *(tptr+3);

    ND_PRINT((ndo, "\n\t  %s Subtype (%u)",
           tok2str(lldp_8021_subtype_values, "unknown", subtype),
           subtype));

    switch (subtype) {
    case LLDP_PRIVATE_8021_SUBTYPE_PORT_VLAN_ID:
        if (tlv_len < 6) {
            return hexdump;
        }
        ND_PRINT((ndo, "\n\t    port vlan id (PVID): %u",
               EXTRACT_16BITS(tptr + 4)));
        break;
    case LLDP_PRIVATE_8021_SUBTYPE_PROTOCOL_VLAN_ID:
        if (tlv_len < 7) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -651,7 +651,7 @@
     int subtype, hexdump = FALSE;
     u_int sublen;
     u_int tval;
-    uint8_t i;
+    u_int i;
 
     if (tlv_len < 4) {
         return hexdump;
@@ -787,9 +787,9 @@
         ND_PRINT((ndo, "\n\t    Application Priority Table"));
         while(i<sublen) {
         	tval=*(tptr+i+5);
-        	ND_PRINT((ndo, "\n\t      Priority: %d, RES: %d, Sel: %d",
-        		 tval >> 5, (tval >> 3) & 0x03, (tval & 0x07)));
-        	ND_PRINT((ndo, "Protocol ID: %d", EXTRACT_16BITS(tptr + i + 5)));
+        	ND_PRINT((ndo, "\n\t      Priority: %u, RES: %u, Sel: %u, Protocol ID: %u",
+        		 tval >> 5, (tval >> 3) & 0x03, (tval & 0x07),
+        		 EXTRACT_16BITS(tptr + i + 5)));
         	i=i+3;
         }
         break;
```
