# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 2351_3
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2351_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 289-329 of the vulnerable file.

		if (!strcmp(item, *p))
			return 1;
	return 0;
}

static void print_value(int output, int num, const char *devname,
			const char *value, const char *name, size_t valsz)
{
	if (output & OUTPUT_VALUE_ONLY) {
		fputs(value, stdout);
		fputc('\n', stdout);

	} else if (output & OUTPUT_UDEV_LIST) {
		print_udev_format(name, value);

	} else if (output & OUTPUT_EXPORT_LIST) {
		if (num == 1 && devname)
			printf("DEVNAME=%s\n", devname);
		fputs(name, stdout);
		fputs("=", stdout);
		safe_print(value, valsz, NULL);
		fputs("\n", stdout);

	} else {
		if (num == 1 && devname)
			printf("%s:", devname);
		fputs(" ", stdout);
		fputs(name, stdout);
		fputs("=\"", stdout);
		safe_print(value, valsz, "\"");
		fputs("\"", stdout);
	}
}

static void print_tags(blkid_dev dev, char *show[], int output)
{
	blkid_tag_iterate	iter;
	const char		*type, *value, *devname;
	int			num = 1;
	static int		first = 1;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -306,7 +306,7 @@
 			printf("DEVNAME=%s\n", devname);
 		fputs(name, stdout);
 		fputs("=", stdout);
-		safe_print(value, valsz, NULL);
+		safe_print(value, valsz, " \\\"'$`<>");
 		fputs("\n", stdout);
 
 	} else {
@@ -315,7 +315,7 @@
 		fputs(" ", stdout);
 		fputs(name, stdout);
 		fputs("=\"", stdout);
-		safe_print(value, valsz, "\"");
+		safe_print(value, valsz, "\"\\");
 		fputs("\"", stdout);
 	}
 }
```
