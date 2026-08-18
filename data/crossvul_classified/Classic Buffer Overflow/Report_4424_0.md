# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4424_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4424_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 7-47 of the vulnerable file.

 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2019, Joyent, Inc.
 */

#include <syslog.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <strings.h>
#include <malloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/mman.h>

#include <libintl.h>

#include "pam_impl.h"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,7 +24,7 @@
  */
 
 /*
- * Copyright (c) 2019, Joyent, Inc.
+ * Copyright 2020, Joyent, Inc.
  */
 
 #include <syslog.h>
@@ -656,9 +656,10 @@
 	 * - we skip leading whitespaces and ignore trailing whitespaces
 	 */
 	while (*ptr != '\0') {
-		if ((*ptr == ' ') || (*ptr == '\t'))
+		if ((*ptr == ' ') || (*ptr == '\t') ||
+		    (index >= PAM_MAX_RESP_SIZE)) {
 			break;
-		else {
+		} else {
 			username[index] = *ptr;
 			index++;
 			ptr++;
@@ -666,9 +667,9 @@
 	}
 
 	/* ret_username will be freed in pam_get_user(). */
-	if ((*ret_username = malloc(index + 1)) == NULL)
+	if (index >= PAM_MAX_RESP_SIZE ||
+	    (*ret_username = strdup(username)) == NULL)
 		return (PAM_BUF_ERR);
-	(void) strcpy(*ret_username, username);
 	return (PAM_SUCCESS);
 }
 
```
