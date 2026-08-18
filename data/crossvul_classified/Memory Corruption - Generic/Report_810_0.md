# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 810_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `810_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 10-50 of the vulnerable file.


static void jsB_new_Number(js_State *J)
{
	js_newnumber(J, js_gettop(J) > 1 ? js_tonumber(J, 1) : 0);
}

static void jsB_Number(js_State *J)
{
	js_pushnumber(J, js_gettop(J) > 1 ? js_tonumber(J, 1) : 0);
}

static void Np_valueOf(js_State *J)
{
	js_Object *self = js_toobject(J, 0);
	if (self->type != JS_CNUMBER) js_typeerror(J, "not a number");
	js_pushnumber(J, self->u.number);
}

static void Np_toString(js_State *J)
{
	char buf[32];
	js_Object *self = js_toobject(J, 0);
	int radix = js_isundefined(J, 1) ? 10 : js_tointeger(J, 1);
	if (self->type != JS_CNUMBER)
		js_typeerror(J, "not a number");
	if (radix == 10) {
		js_pushstring(J, jsV_numbertostring(J, buf, self->u.number));
		return;
	}
	if (radix < 2 || radix > 36)
		js_rangeerror(J, "invalid radix");

	/* lame number to string conversion for any radix from 2 to 36 */
	{
		static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
		char buf[100];
		double number = self->u.number;
		int sign = self->u.number < 0;
		js_Buffer *sb = NULL;
		uint64_t u, limit = ((uint64_t)1<<52);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 
 static void Np_toString(js_State *J)
 {
-	char buf[32];
+	char buf[100];
 	js_Object *self = js_toobject(J, 0);
 	int radix = js_isundefined(J, 1) ? 10 : js_tointeger(J, 1);
 	if (self->type != JS_CNUMBER)
@@ -42,7 +42,6 @@
 	/* lame number to string conversion for any radix from 2 to 36 */
 	{
 		static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
-		char buf[100];
 		double number = self->u.number;
 		int sign = self->u.number < 0;
 		js_Buffer *sb = NULL;
@@ -115,7 +114,8 @@
 /* Customized ToString() on a number */
 static void numtostr(js_State *J, const char *fmt, int w, double n)
 {
-	char buf[32], *e;
+	/* buf needs to fit printf("%.20f", 1e20) */
+	char buf[50], *e;
 	sprintf(buf, fmt, w, n);
 	e = strchr(buf, 'e');
 	if (e) {
```
