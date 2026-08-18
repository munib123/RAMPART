# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 859_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `859_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 301-341 of the vulnerable file.

	struct device * p = *pp;	/* = devlist; */
	while(p)
	{
		if(  p->headers[HEADER_NT].l == headers[HEADER_NT].l
		  && (0==memcmp(p->headers[HEADER_NT].p, headers[HEADER_NT].p, headers[HEADER_NT].l))
		  && p->headers[HEADER_USN].l == headers[HEADER_USN].l
		  && (0==memcmp(p->headers[HEADER_USN].p, headers[HEADER_USN].p, headers[HEADER_USN].l)) )
		{
			/*printf("found! %d\n", (int)(t - p->t));*/
			syslog(LOG_DEBUG, "device updated : %.*s", headers[HEADER_USN].l, headers[HEADER_USN].p);
			p->t = t;
			/* update Location ! */
			if(headers[HEADER_LOCATION].l > p->headers[HEADER_LOCATION].l)
			{
				struct device * tmp;
				tmp = realloc(p, sizeof(struct device)
				    + headers[0].l+headers[1].l+headers[2].l);
				if(!tmp)	/* allocation error */
				{
					syslog(LOG_ERR, "updateDevice() : memory allocation error");
					free(p);
					return 0;
				}
				p = tmp;
				*pp = p;
			}
			memcpy(p->data + p->headers[0].l + p->headers[1].l,
			       headers[2].p, headers[2].l);
			/* TODO : check p->headers[HEADER_LOCATION].l */
			return 0;
		}
		pp = &p->next;
		p = *pp;	/* p = p->next; */
	}
	syslog(LOG_INFO, "new device discovered : %.*s",
	       headers[HEADER_USN].l, headers[HEADER_USN].p);
	/* add */
	{
		char * pc;
		int i;
		p = malloc(  sizeof(struct device)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -318,6 +318,7 @@
 				if(!tmp)	/* allocation error */
 				{
 					syslog(LOG_ERR, "updateDevice() : memory allocation error");
+					*pp = p->next;	/* remove "p" from the list */
 					free(p);
 					return 0;
 				}
```
