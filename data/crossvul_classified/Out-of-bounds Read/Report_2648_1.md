# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2648_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2648_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 573-613 of the vulnerable file.

#define LLDP_INTF_NUMB_SYSPORT_SUBTYPE     3

static const struct tok lldp_intf_numb_subtype_values[] = {
    { LLDP_INTF_NUMB_IFX_SUBTYPE, "Interface Index" },
    { LLDP_INTF_NUMB_SYSPORT_SUBTYPE, "System Port Number" },
    { 0, NULL}
};

#define LLDP_INTF_NUM_LEN                  5

#define LLDP_EVB_MODE_NOT_SUPPORTED	0
#define LLDP_EVB_MODE_EVB_BRIDGE	1
#define LLDP_EVB_MODE_EVB_STATION	2
#define LLDP_EVB_MODE_RESERVED		3

static const struct tok lldp_evb_mode_values[]={
    { LLDP_EVB_MODE_NOT_SUPPORTED, "Not Supported"},
    { LLDP_EVB_MODE_EVB_BRIDGE, "EVB Bridge"},
    { LLDP_EVB_MODE_EVB_STATION, "EVB Staion"},
    { LLDP_EVB_MODE_RESERVED, "Reserved for future Standardization"},
};

#define NO_OF_BITS 8
#define LLDP_PRIVATE_8021_SUBTYPE_CONGESTION_NOTIFICATION_LENGTH  6
#define LLDP_PRIVATE_8021_SUBTYPE_ETS_CONFIGURATION_LENGTH       25
#define LLDP_PRIVATE_8021_SUBTYPE_ETS_RECOMMENDATION_LENGTH      25
#define LLDP_PRIVATE_8021_SUBTYPE_PFC_CONFIGURATION_LENGTH        6
#define LLDP_PRIVATE_8021_SUBTYPE_APPLICATION_PRIORITY_MIN_LENGTH 5
#define LLDP_PRIVATE_8021_SUBTYPE_EVB_LENGTH                      9
#define LLDP_PRIVATE_8021_SUBTYPE_CDCP_MIN_LENGTH                 8

#define LLDP_IANA_SUBTYPE_MUDURL 1

static const struct tok lldp_iana_subtype_values[] =   {
    { LLDP_IANA_SUBTYPE_MUDURL, "MUD-URL" },
    { 0, NULL }
};


static void
print_ets_priority_assignment_table(netdissect_options *ndo,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -590,6 +590,7 @@
     { LLDP_EVB_MODE_EVB_BRIDGE, "EVB Bridge"},
     { LLDP_EVB_MODE_EVB_STATION, "EVB Staion"},
     { LLDP_EVB_MODE_RESERVED, "Reserved for future Standardization"},
+    { 0, NULL},
 };
 
 #define NO_OF_BITS 8
```
