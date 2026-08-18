# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 589_5
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `589_5`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 1313-1353 of the vulnerable file.

    if ((f = fopen(etcFile(W3MCONFIG), "rt")) != NULL) {
	interpret_rc(f);
	fclose(f);
    }
    if ((f = fopen(confFile(CONFIG_FILE), "rt")) != NULL) {
	interpret_rc(f);
	fclose(f);
    }
    if (config_file && (f = fopen(config_file, "rt")) != NULL) {
	interpret_rc(f);
	fclose(f);
    }
    return;

  rc_dir_err:
    no_rc_dir = TRUE;
    if (((tmp_dir = getenv("TMPDIR")) == NULL || *tmp_dir == '\0') &&
	((tmp_dir = getenv("TMP")) == NULL || *tmp_dir == '\0') &&
	((tmp_dir = getenv("TEMP")) == NULL || *tmp_dir == '\0'))
	tmp_dir = "/tmp";
    create_option_search_table();
    goto open_rc;
}


static char optionpanel_src1[] =
    "<html><head><title>Option Setting Panel</title></head><body>\
<h1 align=center>Option Setting Panel<br>(w3m version %s)</b></h1>\
<form method=post action=\"file:///$LIB/" W3MHELPERPANEL_CMDNAME "\">\
<input type=hidden name=mode value=panel>\
<input type=hidden name=cookie value=\"%s\">\
<input type=submit value=\"%s\">\
</form><br>\
<form method=internal action=option>";

static Str optionpanel_str = NULL;

static Str
to_str(struct param_ptr *p)
{
    switch (p->type) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1330,6 +1330,11 @@
 	((tmp_dir = getenv("TMP")) == NULL || *tmp_dir == '\0') &&
 	((tmp_dir = getenv("TEMP")) == NULL || *tmp_dir == '\0'))
 	tmp_dir = "/tmp";
+#ifdef HAVE_MKDTEMP
+    tmp_dir = mkdtemp(Strnew_m_charp(tmp_dir, "/w3m-XXXXXX", NULL)->ptr);
+    if (tmp_dir == NULL)
+	tmp_dir = rc_dir;
+#endif
     create_option_search_table();
     goto open_rc;
 }
```
