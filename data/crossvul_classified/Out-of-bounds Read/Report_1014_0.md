# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1014_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1014_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-42 of the vulnerable file.

/*
 * QLogic iSCSI Offload Driver
 * Copyright (c) 2016 Cavium Inc.
 *
 * This software is available under the terms of the GNU General Public License
 * (GPL) Version 2, available from the file COPYING in the main directory of
 * this source tree.
 */

#include "qedi_dbg.h"
#include <linux/vmalloc.h>

void
qedi_dbg_err(struct qedi_dbg_ctx *qedi, const char *func, u32 line,
	     const char *fmt, ...)
{
	va_list va;
	struct va_format vaf;
	char nfunc[32];

	memset(nfunc, 0, sizeof(nfunc));
	memcpy(nfunc, func, sizeof(nfunc) - 1);

	va_start(va, fmt);

	vaf.fmt = fmt;
	vaf.va = &va;

	if (likely(qedi) && likely(qedi->pdev))
		pr_err("[%s]:[%s:%d]:%d: %pV", dev_name(&qedi->pdev->dev),
		       nfunc, line, qedi->host_no, &vaf);
	else
		pr_err("[0000:00:00.0]:[%s:%d]: %pV", nfunc, line, &vaf);

	va_end(va);
}

void
qedi_dbg_warn(struct qedi_dbg_ctx *qedi, const char *func, u32 line,
	      const char *fmt, ...)
{
	va_list va;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,10 +16,6 @@
 {
 	va_list va;
 	struct va_format vaf;
-	char nfunc[32];
-
-	memset(nfunc, 0, sizeof(nfunc));
-	memcpy(nfunc, func, sizeof(nfunc) - 1);
 
 	va_start(va, fmt);
 
@@ -28,9 +24,9 @@
 
 	if (likely(qedi) && likely(qedi->pdev))
 		pr_err("[%s]:[%s:%d]:%d: %pV", dev_name(&qedi->pdev->dev),
-		       nfunc, line, qedi->host_no, &vaf);
+		       func, line, qedi->host_no, &vaf);
 	else
-		pr_err("[0000:00:00.0]:[%s:%d]: %pV", nfunc, line, &vaf);
+		pr_err("[0000:00:00.0]:[%s:%d]: %pV", func, line, &vaf);
 
 	va_end(va);
 }
@@ -41,10 +37,6 @@
 {
 	va_list va;
 	struct va_format vaf;
-	char nfunc[32];
-
-	memset(nfunc, 0, sizeof(nfunc));
-	memcpy(nfunc, func, sizeof(nfunc) - 1);
 
 	va_start(va, fmt);
 
@@ -56,9 +48,9 @@
 
 	if (likely(qedi) && likely(qedi->pdev))
 		pr_warn("[%s]:[%s:%d]:%d: %pV", dev_name(&qedi->pdev->dev),
-			nfunc, line, qedi->host_no, &vaf);
+			func, line, qedi->host_no, &vaf);
 	else
-		pr_warn("[0000:00:00.0]:[%s:%d]: %pV", nfunc, line, &vaf);
+		pr_warn("[0000:00:00.0]:[%s:%d]: %pV", func, line, &vaf);
 
 ret:
 	va_end(va);
@@ -70,10 +62,6 @@
 {
 	va_list va;
 	struct va_format vaf;
-	char nfunc[32];
-
-	memset(nfunc, 0, sizeof(nfunc));
-	memcpy(nfunc, func, sizeof(nfunc) - 1);
 
 	va_start(va, fmt);
 
@@ -85,10 +73,10 @@
 
 	if (likely(qedi) && likely(qedi->pdev))
 		pr_notice("[%s]:[%s:%d]:%d: %pV",
-			  dev_name(&qedi->pdev->dev), nfunc, line,
+			  dev_name(&qedi->pdev->dev), func, line,
 			  qedi->host_no, &vaf);
 	else
-		pr_notice("[0000:00:00.0]:[%s:%d]: %pV", nfunc, line, &vaf);
+		pr_notice("[0000:00:00.0]:[%s:%d]: %pV", func, line, &vaf);
 
 ret:
 	va_end(va);
@@ -100,10 +88,6 @@
 {
 	va_list va;
 	struct va_format vaf;
-	char nfunc[32];
-
-	memset(nfunc, 0, sizeof(nfunc));
-	memcpy(nfunc, func, sizeof(nfunc) - 1);
 
 	va_start(va, fmt);
 
@@ -115,9 +99,9 @@
 
 	if (likely(qedi) && likely(qedi->pdev))
 		pr_info("[%s]:[%s:%d]:%d: %pV", dev_name(&qedi->pdev->dev),
-			nfunc, line, qedi->host_no, &vaf);
+			func, line, qedi->host_no, &vaf);
 	else
-		pr_info("[0000:00:00.0]:[%s:%d]: %pV", nfunc, line, &vaf);
+		pr_info("[0000:00:00.0]:[%s:%d]: %pV", func, line, &vaf);
 
 ret:
 	va_end(va);
```
