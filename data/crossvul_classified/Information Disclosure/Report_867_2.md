# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 867_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `867_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/*
 * Copyright (C) 2014-2018 Yubico AB - See COPYING
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <security/pam_appl.h>

#define BUFSIZE 1024
#define MAX_DEVS 24
#define PK_LEN 130 // Public key
#define KH_LEN 86  // Key handle
#define RD_LEN 40  // Rounding
#define DEVSIZE (((PK_LEN) + (KH_LEN) + (RD_LEN)))
#define DEFAULT_AUTHFILE_DIR_VAR "XDG_CONFIG_HOME"
#define DEFAULT_AUTHFILE "/Yubico/u2f_keys"
#define DEFAULT_AUTHPENDING_FILE_PATH "/var/run/user/%d/pam-u2f-authpending"
#define DEFAULT_PROMPT "Insert your U2F device, then press ENTER."
#define DEFAULT_CUE "Please touch the device."
#define DEFAULT_ORIGIN_PREFIX "pam://"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2014-2018 Yubico AB - See COPYING
+ * Copyright (C) 2014-2019 Yubico AB - See COPYING
  */
 
 #ifndef UTIL_H
@@ -45,6 +45,7 @@
   const char *appid;
   const char *prompt;
   FILE *debug_file;
+  int is_custom_debug_file;
 } cfg_t;
 
 typedef struct {
```
