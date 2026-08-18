# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in c
**Pair ID:** 1103_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1103_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```c
Lines 50-90 of the vulnerable file.


static void pair_int(const char *key, int val, int mode, bool last) {
	pair (key, sdb_fmt ("%d", val), mode, last);
}

static void pair_ut64(const char *key, ut64 val, int mode, bool last) {
	pair (key, sdb_fmt ("%"PFMT64d, val), mode, last);
}

static char *__filterQuotedShell(const char *arg) {
	r_return_val_if_fail (arg, NULL);
	char *a = malloc (strlen (arg) + 1);
	if (!a) {
		return NULL;
	}
	char *b = a;
	while (*arg) {
		switch (*arg) {
		case ' ':
		case '=':
		case '\r':
		case '\n':
			break;
		default:
			*b++ = *arg;
			break;
		}
		arg++;
	}
	*b = 0;
	return a;
}
// TODO: move into libr/util/name.c
static char *__filterShell(const char *arg) {
	r_return_val_if_fail (arg, NULL);
	char *a = malloc (strlen (arg) + 1);
	if (!a) {
		return NULL;
	}
	char *b = a;
	while (*arg) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,6 +67,8 @@
 		switch (*arg) {
 		case ' ':
 		case '=':
+		case '"':
+		case '\\':
 		case '\r':
 		case '\n':
 			break;
@@ -88,15 +90,17 @@
 	}
 	char *b = a;
 	while (*arg) {
-		switch (*arg) {
+		char ch = *arg;
+		switch (ch) {
 		case '@':
 		case '`':
 		case '|':
 		case ';':
+		case '=':
 		case '\n':
 			break;
 		default:
-			*b++ = *arg;
+			*b++ = ch;
 			break;
 		}
 		arg++;
@@ -2225,10 +2229,10 @@
 						char *m = __filterShell (module);
 						*p = 0;
 						if (r->bin->prefix) {
-							r_cons_printf ("k bin/pe/%s/%d=%s.%s\n",
+							r_cons_printf ("\"k bin/pe/%s/%d=%s.%s\"\n",
 								module, symbol->ordinal, r->bin->prefix, symname);
 						} else {
-							r_cons_printf ("k bin/pe/%s/%d=%s\n",
+							r_cons_printf ("\"k bin/pe/%s/%d=%s\"\n",
 								module, symbol->ordinal, symname);
 						}
 						free (symname);
```
