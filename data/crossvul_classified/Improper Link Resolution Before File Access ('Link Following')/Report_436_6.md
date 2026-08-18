# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_6
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_6`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 15-55 of the vulnerable file.

 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2012 John Southworth, <john.southworth@vyatta.com>
 * Copyright (C) 2015-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <inttypes.h>

#include "logger.h"

#include "vrrp.h"
#include "vrrp_data.h"
#include "vrrp_print.h"

static const char *dump_file = "/tmp/keepalived.data";
static const char *stats_file = "/tmp/keepalived.stats";

void
vrrp_print_data(void)
{
	FILE *file = fopen (dump_file, "w");

	if (!file) {
		log_message(LOG_INFO, "Can't open %s (%d: %s)",
			dump_file, errno, strerror(errno));
		return;
	}

	dump_data_vrrp(file);

	fclose(file);
}

void
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,7 @@
 #include "vrrp.h"
 #include "vrrp_data.h"
 #include "vrrp_print.h"
+#include "utils.h"
 
 static const char *dump_file = "/tmp/keepalived.data";
 static const char *stats_file = "/tmp/keepalived.stats";
@@ -39,7 +40,7 @@
 void
 vrrp_print_data(void)
 {
-	FILE *file = fopen (dump_file, "w");
+	FILE *file = fopen_safe(dump_file, "w");
 
 	if (!file) {
 		log_message(LOG_INFO, "Can't open %s (%d: %s)",
@@ -55,8 +56,9 @@
 void
 vrrp_print_stats(void)
 {
-	FILE *file;
-	file = fopen (stats_file, "w");
+	FILE *file = fopen_safe(stats_file, "w");
+	element e;
+	vrrp_t *vrrp;
 
 	if (!file) {
 		log_message(LOG_INFO, "Can't open %s (%d: %s)",
@@ -64,19 +66,14 @@
 		return;
 	}
 
-	list l = vrrp_data->vrrp;
-	element e;
-	vrrp_t *vrrp;
 
-	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
-		vrrp = ELEMENT_DATA(e);
+	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
 		fprintf(file, "VRRP Instance: %s\n", vrrp->iname);
 		fprintf(file, "  Advertisements:\n");
 		fprintf(file, "    Received: %" PRIu64 "\n", vrrp->stats->advert_rcvd);
 		fprintf(file, "    Sent: %d\n", vrrp->stats->advert_sent);
 		fprintf(file, "  Became master: %d\n", vrrp->stats->become_master);
-		fprintf(file, "  Released master: %d\n",
-			vrrp->stats->release_master);
+		fprintf(file, "  Released master: %d\n", vrrp->stats->release_master);
 		fprintf(file, "  Packet Errors:\n");
 		fprintf(file, "    Length: %" PRIu64 "\n", vrrp->stats->packet_len_err);
 		fprintf(file, "    TTL: %" PRIu64 "\n", vrrp->stats->ip_ttl_err);
```
