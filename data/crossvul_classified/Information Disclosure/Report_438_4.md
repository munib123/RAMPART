# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 438_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `438_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 18-58 of the vulnerable file.

 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#ifdef _HAVE_SCHED_RT_
#include <sched.h>
#endif
#include <strings.h>

#ifdef _WITH_SNMP_
#include "snmp.h"
#endif

#include "global_parser.h"
#include "global_data.h"
#include "main.h"
#include "parser.h"
#include "smtp.h"
#include "utils.h"
#include "logger.h"

#if HAVE_DECL_CLONE_NEWNET
#include "namespaces.h"
#endif

#define LVS_MAX_TIMEOUT		(86400*31)	/* 31 days */

/* data handlers */
/* Global def handlers */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,6 +35,8 @@
 #include <sched.h>
 #endif
 #include <strings.h>
+#include <sys/types.h>
+#include <sys/stat.h>
 
 #ifdef _WITH_SNMP_
 #include "snmp.h"
@@ -1340,6 +1342,76 @@
 	global_data->no_checker_emails = res;
 }
 #endif
+
+static void
+umask_handler(vector_t *strvec)
+{
+	long umask_long;
+	mode_t umask_val = 0;
+	char *mask = strvec_slot(strvec, 1);
+	char *endptr;
+	unsigned i;
+	char *p;
+
+	if (umask_cmdline) {
+		log_message(LOG_INFO, "umask command line option specified, ignoring config option");
+		return;
+	}
+
+	if (isdigit(mask[0])) {
+		if (vector_size(strvec) != 2) {
+			report_config_error(CONFIG_GENERAL_ERROR, "%s parameter(s) to umask option", vector_size(strvec) == 1 ? "Missing" : "Extra");
+			return;
+		}
+		umask_long = strtol(mask, &endptr, 0);
+		if (*endptr || umask_long < 0 || umask_long & ~0777L) {
+			report_config_error(CONFIG_GENERAL_ERROR, "invalid umask value %s", mask);
+			return;
+		}
+		umask_val = umask_long & 0777;
+	}
+	else {
+		bool need_or = false;
+		for (i = 1; i < vector_size(strvec); i++) {
+			for (p = strvec_slot(strvec, i); *p; ) {
+				if (need_or) {
+					if (*p == '|') {
+						need_or = false;
+						p++;
+						continue;
+					}
+
+					report_config_error(CONFIG_GENERAL_ERROR, "Invalid umask syntax %s", FMT_STR_VSLOT(strvec, i));
+					return;
+				}
+
+				if      (!strncmp(p, "IRUSR", 5)) umask_val |= S_IRUSR;
+				else if (!strncmp(p, "IWUSR", 5)) umask_val |= S_IWUSR;
+				else if (!strncmp(p, "IXUSR", 5)) umask_val |= S_IXUSR;
+				else if (!strncmp(p, "IRGRP", 5)) umask_val |= S_IRGRP;
+				else if (!strncmp(p, "IWGRP", 5)) umask_val |= S_IWGRP;
+				else if (!strncmp(p, "IXGRP", 5)) umask_val |= S_IXGRP;
+				else if (!strncmp(p, "IROTH", 5)) umask_val |= S_IROTH;
+				else if (!strncmp(p, "IWOTH", 5)) umask_val |= S_IWOTH;
+				else if (!strncmp(p, "IXOTH", 5)) umask_val |= S_IXOTH;
+				else {
+					report_config_error(CONFIG_GENERAL_ERROR, "Unknown umask bit %s", p);
+					return;
+				}
+
+				p += 5;
+				need_or = true;
+			}
+		}
+		if (!need_or) {
+			report_config_error(CONFIG_GENERAL_ERROR, "umask missing bit value");
+			return;
+		}
+	}
+
+	global_data->umask = umask_val;
+	umask(umask_val);
+}
 
 void
 init_global_keywords(bool global_active)
@@ -1483,4 +1555,5 @@
 	install_keyword("vrrp_rx_bufs_policy", &vrrp_rx_bufs_policy_handler);
 	install_keyword("vrrp_rx_bufs_multiplier", &vrrp_rx_bufs_multiplier_handler);
 #endif
-}
+	install_keyword("umask", &umask_handler);
+}
```
