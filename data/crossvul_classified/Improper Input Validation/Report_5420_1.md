# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5420_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5420_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 103-143 of the vulnerable file.

    else if (strcasecmp(oval, "middle") == 0)
	*valign = VALIGN_MIDDLE;
    else
	return 0;
    return 1;
}

extern Hash_si tagtable;
#define MAX_TAG_LEN 64

struct parsed_tag *
parse_tag(char **s, int internal)
{
    struct parsed_tag *tag = NULL;
    int tag_id;
    char tagname[MAX_TAG_LEN], attrname[MAX_TAG_LEN];
    char *p, *q;
    int i, attr_id = 0, nattr;

    /* Parse tag name */
    q = (*s) + 1;
    p = tagname;
    if (*q == '/') {
	*(p++) = *(q++);
	SKIP_BLANKS(q);
    }
    while (*q && !IS_SPACE(*q) && !(tagname[0] != '/' && *q == '/') &&
	   *q != '>' && p - tagname < MAX_TAG_LEN - 1) {
	*(p++) = TOLOWER(*q);
	q++;
    }
    *p = '\0';
    while (*q && !IS_SPACE(*q) && !(tagname[0] != '/' && *q == '/') &&
	   *q != '>')
	q++;

    tag_id = getHash_si(&tagtable, tagname, HTML_UNKNOWN);

    if (tag_id == HTML_UNKNOWN ||
	(!internal && TagMAP[tag_id].flag & TFLG_INT))
	goto skip_parse_tagarg;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,6 +120,7 @@
     int i, attr_id = 0, nattr;
 
     /* Parse tag name */
+    tagname[0] = '\0';
     q = (*s) + 1;
     p = tagname;
     if (*q == '/') {
```
