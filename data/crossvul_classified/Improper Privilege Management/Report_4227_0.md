# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 4227_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4227_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 1-38 of the vulnerable file.


#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/watcher.h>
#include <net-snmp/agent/agent_callbacks.h>

#include "agent/extend.h"
#include "utilities/execute.h"
#include "struct.h"

#ifndef USING_UCD_SNMP_EXTENSIBLE_MODULE
#include "util_funcs/header_simple_table.h"
#include "mibdefs.h"
#define SHELLCOMMAND 3
#endif

netsnmp_feature_require(extract_table_row_data);
netsnmp_feature_require(table_data_delete_table);
#ifndef NETSNMP_NO_WRITE_SUPPORT
netsnmp_feature_require(insert_table_row);
#endif /* NETSNMP_NO_WRITE_SUPPORT */

oid  ns_extend_oid[]    = { 1, 3, 6, 1, 4, 1, 8072, 1, 3, 2 };

typedef struct extend_registration_block_s {
    netsnmp_table_data *dinfo;
    oid                *root_oid;
    size_t              oid_len;
    long                num_entries;
    netsnmp_extend     *ehead;
    netsnmp_handler_registration       *reg[4];
    struct extend_registration_block_s *next;
} extend_registration_block;
extend_registration_block *ereg_head = NULL;


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,12 @@
 #include "mibdefs.h"
 #define SHELLCOMMAND 3
 #endif
+
+/*  This mib is potentially dangerous to turn on by default, since it
+ *  allows arbitrary commands to be set by anyone with SNMP WRITE
+ *  access to the MIB table.  If all of your users are "root" level
+ *  users, then it may be safe to turn on. */
+#define ENABLE_EXTEND_WRITE_ACCESS 0
 
 netsnmp_feature_require(extract_table_row_data);
 netsnmp_feature_require(table_data_delete_table);
@@ -742,7 +748,7 @@
          *
          **********/
 
-#ifndef NETSNMP_NO_WRITE_SUPPORT
+#if !defined(NETSNMP_NO_WRITE_SUPPORT) && ENABLE_EXTEND_WRITE_ACCESS
         case MODE_SET_RESERVE1:
             /*
              * Validate the new assignments
@@ -1068,7 +1074,7 @@
                 }
             }
             break;
-#endif /* !NETSNMP_NO_WRITE_SUPPORT */ 
+#endif /* !NETSNMP_NO_WRITE_SUPPORT and ENABLE_EXTEND_WRITE_ACCESS */
 
         default:
             netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);
@@ -1076,7 +1082,7 @@
         }
     }
 
-#ifndef NETSNMP_NO_WRITE_SUPPORT
+#if !defined(NETSNMP_NO_WRITE_SUPPORT) && ENABLE_EXTEND_WRITE_ACCESS
     /*
      * If we're marking a given row as active,
      *  then we need to check that it's ready.
@@ -1101,7 +1107,7 @@
             }
         }
     }
-#endif /* !NETSNMP_NO_WRITE_SUPPORT */
+#endif /* !NETSNMP_NO_WRITE_SUPPORT && ENABLE_EXTEND_WRITE_ACCESS */
     
     return SNMP_ERR_NOERROR;
 }
@@ -1587,7 +1593,7 @@
     idx = name[name_len-1] -1;
     exten = &compatability_entries[ idx ];
 
-#ifndef NETSNMP_NO_WRITE_SUPPORT
+#if !defined(NETSNMP_NO_WRITE_SUPPORT) && ENABLE_EXTEND_WRITE_ACCESS
     switch (action) {
     case MODE_SET_RESERVE1:
         if (var_val_type != ASN_INTEGER) {
@@ -1608,7 +1614,7 @@
     case MODE_SET_COMMIT:
         netsnmp_cache_check_and_reload( exten->efix_entry->cache );
     }
-#endif /* !NETSNMP_NO_WRITE_SUPPORT */
+#endif /* !NETSNMP_NO_WRITE_SUPPORT && ENABLE_EXTEND_WRITE_ACCESS */
     return SNMP_ERR_NOERROR;
 }
 #endif /* USING_UCD_SNMP_EXTENSIBLE_MODULE */
```
