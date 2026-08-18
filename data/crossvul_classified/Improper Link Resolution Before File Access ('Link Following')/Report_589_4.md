# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 589_4
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `589_4`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 5955-5995 of the vulnerable file.

}

void
w3m_exit(int i)
{
#ifdef USE_MIGEMO
    init_migemo();		/* close pipe to migemo */
#endif
    stopDownload();
    deleteFiles();
#ifdef USE_SSL
    free_ssl_ctx();
#endif
    disconnectFTP();
#ifdef USE_NNTP
    disconnectNews();
#endif
#ifdef __MINGW32_VERSION
    WSACleanup();
#endif
    exit(i);
}

DEFUN(execCmd, COMMAND, "Invoke w3m function(s)")
{
    char *data, *p;
    int cmd;

    CurrentKeyData = NULL;	/* not allowed in w3m-control: */
    data = searchKeyData();
    if (data == NULL || *data == '\0') {
	data = inputStrHist("command [; ...]: ", "", TextHist);
	if (data == NULL) {
	    displayBuffer(Currentbuf, B_NORMAL);
	    return;
	}
    }
    /* data: FUNC [DATA] [; FUNC [DATA] ...] */
    while (*data) {
	SKIP_BLANKS(data);
	if (*data == ';') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5972,6 +5972,13 @@
 #ifdef __MINGW32_VERSION
     WSACleanup();
 #endif
+#ifdef HAVE_MKDTEMP
+    if (no_rc_dir && tmp_dir != rc_dir)
+	if (rmdir(tmp_dir) != 0) {
+	    fprintf(stderr, "Can't remove temporary directory (%s)!\n", tmp_dir);
+	    exit(1);
+	}
+#endif
     exit(i);
 }
 
```
