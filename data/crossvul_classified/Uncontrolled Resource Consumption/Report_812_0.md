# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 812_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `812_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 12-52 of the vulnerable file.


	obj = jsV_newobject(J, JS_CREGEXP, J->RegExp_prototype);

	opts = 0;
	if (flags & JS_REGEXP_I) opts |= REG_ICASE;
	if (flags & JS_REGEXP_M) opts |= REG_NEWLINE;

	prog = js_regcompx(J->alloc, J->actx, pattern, opts, &error);
	if (!prog)
		js_syntaxerror(J, "regular expression: %s", error);

	obj->u.r.prog = prog;
	obj->u.r.source = js_strdup(J, pattern);
	obj->u.r.flags = flags;
	obj->u.r.last = 0;
	js_pushobject(J, obj);
}

void js_RegExp_prototype_exec(js_State *J, js_Regexp *re, const char *text)
{
	int i;
	int opts;
	Resub m;

	opts = 0;
	if (re->flags & JS_REGEXP_G) {
		if (re->last > strlen(text)) {
			re->last = 0;
			js_pushnull(J);
			return;
		}
		if (re->last > 0) {
			text += re->last;
			opts |= REG_NOTBOL;
		}
	}

	if (!js_regexec(re->prog, text, &m, opts)) {
		js_newarray(J);
		js_pushstring(J, text);
		js_setproperty(J, -2, "input");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
 
 void js_RegExp_prototype_exec(js_State *J, js_Regexp *re, const char *text)
 {
+	int result;
 	int i;
 	int opts;
 	Resub m;
@@ -46,7 +47,10 @@
 		}
 	}
 
-	if (!js_regexec(re->prog, text, &m, opts)) {
+	result = js_regexec(re->prog, text, &m, opts);
+	if (result < 0)
+		js_error(J, "regexec failed");
+	if (result == 0) {
 		js_newarray(J);
 		js_pushstring(J, text);
 		js_setproperty(J, -2, "input");
@@ -71,6 +75,7 @@
 {
 	js_Regexp *re;
 	const char *text;
+	int result;
 	int opts;
 	Resub m;
 
@@ -90,7 +95,10 @@
 		}
 	}
 
-	if (!js_regexec(re->prog, text, &m, opts)) {
+	result = js_regexec(re->prog, text, &m, opts);
+	if (result < 0)
+		js_error(J, "regexec failed");
+	if (result == 0) {
 		if (re->flags & JS_REGEXP_G)
 			re->last = re->last + (m.sub[0].ep - text);
 		js_pushboolean(J, 1);
```
