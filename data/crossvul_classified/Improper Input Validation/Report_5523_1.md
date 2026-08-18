# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5523_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5523_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 77-117 of the vulnerable file.

    int repl_utf8;
    int high_surrogate = 0;
#else
    char buf[1];
#endif

#if defined(__GNUC__) && defined(UNICODE_HTML_PARSER)
    /* gcc -Wall reports this variable as possibly used uninitialized */
    repl_utf8 = 0;
#endif

    while (s < end) {
	assert(t <= s);

	if ((*t++ = *s++) != '&')
	    continue;

	ent_start = s;
	repl = 0;

	if (*s == '#') {
	    UV num = 0;
	    UV prev = 0;
	    int ok = 0;
	    s++;
	    if (*s == 'x' || *s == 'X') {
		s++;
		while (*s) {
		    char *tmp = strchr(PL_hexdigit, *s);
		    if (!tmp)
			break;
		    num = num << 4 | ((tmp - PL_hexdigit) & 15);
		    if (prev && num <= prev) {
			/* overflow */
			ok = 0;
			break;
		    }
		    prev = num;
		    s++;
		    ok = 1;
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,14 +94,14 @@
 	ent_start = s;
 	repl = 0;
 
-	if (*s == '#') {
+	if (s < end && *s == '#') {
 	    UV num = 0;
 	    UV prev = 0;
 	    int ok = 0;
 	    s++;
-	    if (*s == 'x' || *s == 'X') {
+	    if (s < end && (*s == 'x' || *s == 'X')) {
 		s++;
-		while (*s) {
+		while (s < end) {
 		    char *tmp = strchr(PL_hexdigit, *s);
 		    if (!tmp)
 			break;
@@ -117,7 +117,7 @@
 		}
 	    }
 	    else {
-		while (isDIGIT(*s)) {
+		while (s < end && isDIGIT(*s)) {
 		    num = num * 10 + (*s - '0');
 		    if (prev && num < prev) {
 			/* overflow */
@@ -180,7 +180,7 @@
 	}
 	else {
 	    char *ent_name = s;
-	    while (isALNUM(*s))
+	    while (s < end && isALNUM(*s))
 		s++;
 	    if (ent_name != s && entity2char) {
 		SV** svp;
@@ -216,7 +216,7 @@
 
 	if (repl) {
 	    char *repl_allocated = 0;
-	    if (*s == ';')
+	    if (s < end && *s == ';')
 		s++;
 	    t--;  /* '&' already copied, undo it */
 
```
