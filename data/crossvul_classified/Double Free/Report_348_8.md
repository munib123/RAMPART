# CrossVul Fix Pair: Double Free in c
**Pair ID:** 348_8
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `348_8`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 4-44 of the vulnerable file.

 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include "libopensc/sc-ossl-compat.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "libopensc/pkcs15.h"
#include "common/compat_strlcpy.h"
#include "common/compat_strlcat.h"
#include "util.h"

static const char *app_name = "cryptoflex-tool";

static char * opt_reader = NULL;
static int opt_wait = 0;
static int opt_key_num = 1, opt_pin_num = -1;
static int verbose = 0;
static int opt_exponent = 3;
static int opt_mod_length = 1024;
static int opt_key_count = 1;
static int opt_pin_attempts = 10;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
 #include "config.h"
 
 #include "libopensc/sc-ossl-compat.h"
+#include "libopensc/internal.h"
 #include <openssl/bn.h>
 #include <openssl/rsa.h>
 #include <openssl/x509.h>
@@ -331,7 +332,7 @@
 		fprintf(stderr, "Unable to select public key file: %s\n", sc_strerror(r));
 		return 2;
 	}
-	bufsize = file->size;
+	bufsize = MIN(file->size, sizeof buf);
 	sc_file_free(file);
 	r = sc_read_binary(card, 0, buf, bufsize, 0);
 	if (r < 0) {
@@ -382,7 +383,7 @@
 	e = sc_file_get_acl_entry(file, SC_AC_OP_READ);
 	if (e == NULL || e->method == SC_AC_NEVER)
 		return 10;
-	bufsize = file->size;
+	bufsize = MIN(file->size, sizeof buf);
 	sc_file_free(file);
 	r = sc_read_binary(card, 0, buf, bufsize, 0);
 	if (r < 0) {
```
