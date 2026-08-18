# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_3
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_3`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 577-617 of the vulnerable file.

/* run if bus name or connection are lost */
static void
on_name_lost(GDBusConnection *connection,
	     const gchar     *name,
	     __attribute__((unused)) gpointer user_data)
{
	log_message(LOG_INFO, "Lost the name %s on the session bus", name);
	global_connection = connection;
	g_hash_table_foreach_remove(objects, unregister_object, NULL);
	objects = NULL;
	global_connection = NULL;
}

static gchar*
read_file(gchar* filepath)
{
	FILE * f;
	size_t length;
	gchar *ret = NULL;

	f = fopen(filepath, "rb");
	if (f) {
		fseek(f, 0, SEEK_END);
		length = (size_t)ftell(f);
		fseek(f, 0, SEEK_SET);

		/* We can't use MALLOC since it isn't thread safe */
		ret = MALLOC(length + 1);
		if (ret) {
			if (fread(ret, length, 1, f) != 1) {
				log_message(LOG_INFO, "Failed to read all of %s", filepath);
			}
			ret[length] = '\0';
		}
		else
			log_message(LOG_INFO, "Unable to read Dbus file %s", filepath);

		fclose(f);
	}
	return ret;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -594,7 +594,7 @@
 	size_t length;
 	gchar *ret = NULL;
 
-	f = fopen(filepath, "rb");
+	f = fopen(filepath, "r");
 	if (f) {
 		fseek(f, 0, SEEK_END);
 		length = (size_t)ftell(f);
```
