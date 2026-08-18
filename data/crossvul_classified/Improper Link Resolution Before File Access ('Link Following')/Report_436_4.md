# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_4
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_4`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 20-60 of the vulnerable file.

 *
 * Copyright (C) 2017 Damien Clabaut, <Damien.Clabaut@corp.ovh.com>
 * Copyright (C) 2017-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"
#include "vrrp_json.h"

#include <errno.h>
#include <stdio.h>
#include <json.h>

#include "vrrp.h"
#include "vrrp_track.h"
#include "list.h"
#include "vrrp_data.h"
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#include "logger.h"
#include "timer.h"

static inline double
timeval_to_double(const timeval_t *t)
{
	/* The casts are necessary to avoid conversion warnings */
	return (double)t->tv_sec + (double)t->tv_usec / TIMER_HZ_FLOAT;
}

void
vrrp_print_json(void)
{
	FILE *file;
	element e;
	struct json_object *array;

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return;

	file = fopen ("/tmp/keepalived.json","w");
	if (!file) {
		log_message(LOG_INFO, "Can't open /tmp/keepalived.json (%d: %s)",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,6 +37,7 @@
 #include "vrrp_iprule.h"
 #include "logger.h"
 #include "timer.h"
+#include "utils.h"
 
 static inline double
 timeval_to_double(const timeval_t *t)
@@ -55,7 +56,7 @@
 	if (LIST_ISEMPTY(vrrp_data->vrrp))
 		return;
 
-	file = fopen ("/tmp/keepalived.json","w");
+	file = fopen_safe("/tmp/keepalived.json", "w");
 	if (!file) {
 		log_message(LOG_INFO, "Can't open /tmp/keepalived.json (%d: %s)",
 			errno, strerror(errno));
```
