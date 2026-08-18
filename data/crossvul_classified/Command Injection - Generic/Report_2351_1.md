# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 2351_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2351_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 9-49 of the vulnerable file.

 * GNU Lesser General Public License.
 * %End-Header%
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "closestream.h"

#include "blkidP.h"

static int save_dev(blkid_dev dev, FILE *file)
{
	struct list_head *p;

	if (!dev || dev->bid_name[0] != '/')
		return 0;

	DBG(SAVE, ul_debug("device %s, type %s", dev->bid_name, dev->bid_type ?
		   dev->bid_type : "(null)"));

	fprintf(file, "<device DEVNO=\"0x%04lx\" TIME=\"%ld.%ld\"",
			(unsigned long) dev->bid_devno,
			(long) dev->bid_time,
			(long) dev->bid_utime);

	if (dev->bid_pri)
		fprintf(file, " PRI=\"%d\"", dev->bid_pri);
	list_for_each(p, &dev->bid_tags) {
		blkid_tag tag = list_entry(p, struct blkid_struct_tag, bit_tags);
		fprintf(file, " %s=\"%s\"", tag->bit_name,tag->bit_val);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,21 @@
 
 #include "blkidP.h"
 
+
+static void save_quoted(const char *data, FILE *file)
+{
+	const char *p;
+
+	fputc('"', file);
+	for (p = data; p && *p; p++) {
+		if ((unsigned char) *p == 0x22 ||		/* " */
+		    (unsigned char) *p == 0x5c)			/* \ */
+			fputc('\\', file);
+
+		fputc(*p, file);
+	}
+	fputc('"', file);
+}
 static int save_dev(blkid_dev dev, FILE *file)
 {
 	struct list_head *p;
@@ -43,9 +58,14 @@
 
 	if (dev->bid_pri)
 		fprintf(file, " PRI=\"%d\"", dev->bid_pri);
+
 	list_for_each(p, &dev->bid_tags) {
 		blkid_tag tag = list_entry(p, struct blkid_struct_tag, bit_tags);
-		fprintf(file, " %s=\"%s\"", tag->bit_name,tag->bit_val);
+
+		fputc(' ', file);			/* space between tags */
+		fputs(tag->bit_name, file);		/* tag NAME */
+		fputc('=', file);			/* separator between NAME and VALUE */
+		save_quoted(tag->bit_val, file);	/* tag "VALUE" */
 	}
 	fprintf(file, ">%s</device>\n", dev->bid_name);
 
```
