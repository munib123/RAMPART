# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 812_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `812_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1-26 of the vulnerable file.

#include "jsi.h"
#include "jsvalue.h"
#include "jsbuiltin.h"
#include "utf.h"
#include "regexp.h"

static const char *checkstring(js_State *J, int idx)
{
	if (!js_iscoercible(J, idx))
		js_typeerror(J, "string function called on null or undefined");
	return js_tostring(J, idx);
}

int js_runeat(js_State *J, const char *s, int i)
{
	Rune rune = 0;
	while (i-- >= 0) {
		rune = *(unsigned char*)s;
		if (rune < Runeself) {
			if (rune == 0)
				return 0;
			++s;
		} else
			s += chartorune(&rune, s);
	}
	return rune;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,14 @@
 #include "jsbuiltin.h"
 #include "utf.h"
 #include "regexp.h"
+
+static int js_doregexec(js_State *J, Reprog *prog, const char *string, Resub *sub, int eflags)
+{
+	int result = js_regexec(prog, string, sub, eflags);
+	if (result < 0)
+		js_error(J, "regexec failed");
+	return result;
+}
 
 static const char *checkstring(js_State *J, int idx)
 {
@@ -343,7 +351,7 @@
 	a = text;
 	e = text + strlen(text);
 	while (a <= e) {
-		if (js_regexec(re->prog, a, &m, a > text ? REG_NOTBOL : 0))
+		if (js_doregexec(J, re->prog, a, &m, a > text ? REG_NOTBOL : 0))
 			break;
 
 		b = m.sub[0].sp;
@@ -380,7 +388,7 @@
 
 	re = js_toregexp(J, -1);
 
-	if (!js_regexec(re->prog, text, &m, 0))
+	if (!js_doregexec(J, re->prog, text, &m, 0))
 		js_pushnumber(J, js_utfptrtoidx(text, m.sub[0].sp));
 	else
 		js_pushnumber(J, -1);
@@ -397,7 +405,7 @@
 	source = checkstring(J, 0);
 	re = js_toregexp(J, 1);
 
-	if (js_regexec(re->prog, source, &m, 0)) {
+	if (js_doregexec(J, re->prog, source, &m, 0)) {
 		js_copy(J, 0);
 		return;
 	}
@@ -471,7 +479,7 @@
 			else
 				goto end;
 		}
-		if (!js_regexec(re->prog, source, &m, REG_NOTBOL))
+		if (!js_doregexec(J, re->prog, source, &m, REG_NOTBOL))
 			goto loop;
 	}
 
@@ -576,7 +584,7 @@
 
 	/* splitting the empty string */
 	if (e == text) {
-		if (js_regexec(re->prog, text, &m, 0)) {
+		if (js_doregexec(J, re->prog, text, &m, 0)) {
 			if (len == limit) return;
 			js_pushliteral(J, "");
 			js_setindex(J, -2, 0);
@@ -586,7 +594,7 @@
 
 	p = a = text;
 	while (a < e) {
-		if (js_regexec(re->prog, a, &m, a > text ? REG_NOTBOL : 0))
+		if (js_doregexec(J, re->prog, a, &m, a > text ? REG_NOTBOL : 0))
 			break; /* no match */
 
 		b = m.sub[0].sp;
```
